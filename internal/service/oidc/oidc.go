package oidc

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	goidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/eduardolat/pgbackweb/internal/config"
	"github.com/eduardolat/pgbackweb/internal/database/dbgen"
	"github.com/eduardolat/pgbackweb/internal/service/users"
)

// providerName identifies this instance's single configured OIDC provider
// in the users.oidc_provider column. There is only ever one, so a fixed
// name is enough; it's not exposed to end users.
const providerName = "oidc"

// ErrIdentityNotRecognized is returned when an OIDC login can't be resolved
// to the single user allowed on this instance: the claimed email doesn't
// match the existing user, or it matches a user already linked to a
// different identity.
var ErrIdentityNotRecognized = errors.New(
	"this identity is not recognized; only one user is allowed on this instance",
)

// ErrEmailNotVerified is returned when linking would require trusting an
// unverified email claim from the identity provider.
var ErrEmailNotVerified = errors.New(
	"the identity provider did not report a verified email address",
)

type Service struct {
	env          config.Env
	usersService *users.Service

	enabled      bool
	oauth2Config oauth2.Config
	verifier     *goidc.IDTokenVerifier
}

// New creates the OIDC service. When PBW_OIDC_ENABLED is false, it returns
// immediately without any network calls, so a disabled OIDC configuration
// never requires the identity provider to be reachable at startup.
func New(env config.Env, usersService *users.Service) (*Service, error) {
	if !env.PBW_OIDC_ENABLED {
		return &Service{env: env, usersService: usersService}, nil
	}

	provider, err := goidc.NewProvider(context.Background(), env.PBW_OIDC_ISSUER_URL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider: %w", err)
	}

	return &Service{
		env:          env,
		usersService: usersService,
		enabled:      true,
		oauth2Config: oauth2.Config{
			ClientID:     env.PBW_OIDC_CLIENT_ID,
			ClientSecret: env.PBW_OIDC_CLIENT_SECRET,
			RedirectURL:  env.PBW_OIDC_REDIRECT_URL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{goidc.ScopeOpenID, goidc.ScopeProfile, goidc.ScopeEmail},
		},
		verifier: provider.Verifier(&goidc.Config{ClientID: env.PBW_OIDC_CLIENT_ID}),
	}, nil
}

func (s *Service) IsEnabled() bool {
	return s.enabled
}

// GenerateState returns a random, URL-safe token to be stored in a
// short-lived cookie and echoed back by the identity provider, so the
// callback can be verified as belonging to a login this instance started.
func (s *Service) GenerateState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GetAuthURL returns the identity provider's authorization URL to redirect
// the user to, embedding the given CSRF state.
func (s *Service) GetAuthURL(state string) string {
	return s.oauth2Config.AuthCodeURL(state)
}

type claims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// HandleCallback exchanges the authorization code for tokens, verifies the
// ID token, and resolves the resulting identity to the single user allowed
// on this instance — creating that user on a fresh install, refreshing an
// already-linked user's profile, or linking an unlinked local user by
// verified email. It never inserts a second user row.
func (s *Service) HandleCallback(ctx context.Context, code string) (dbgen.User, error) {
	token, err := s.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return dbgen.User{}, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return dbgen.User{}, errors.New("token response did not include an id_token")
	}

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return dbgen.User{}, fmt.Errorf("failed to verify id token: %w", err)
	}

	var c claims
	if err := idToken.Claims(&c); err != nil {
		return dbgen.User{}, fmt.Errorf("failed to parse id token claims: %w", err)
	}
	if c.Subject == "" || c.Email == "" {
		return dbgen.User{}, errors.New("identity provider did not return sub and email claims")
	}
	if c.Name == "" {
		c.Name = strings.SplitN(c.Email, "@", 2)[0]
	}

	usersQty, err := s.usersService.GetUsersQty(ctx)
	if err != nil {
		return dbgen.User{}, err
	}

	var byIdentity, byEmail *dbgen.User
	if usersQty > 0 {
		found, user, err := s.usersService.GetUserByOIDCIdentity(ctx, providerName, c.Subject)
		if err != nil {
			return dbgen.User{}, err
		}
		if found {
			byIdentity = &user
		}

		if byIdentity == nil {
			user, err := s.usersService.GetUserByEmail(ctx, c.Email)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return dbgen.User{}, err
			}
			if err == nil {
				byEmail = &user
			}
		}
	}

	switch decideResolution(usersQty, byIdentity, byEmail) {
	case resolveCreateFirstUser:
		return s.usersService.CreateUser(ctx, dbgen.UsersServiceCreateUserParams{
			Name:         c.Name,
			Email:        c.Email,
			OidcProvider: sql.NullString{String: providerName, Valid: true},
			OidcSubject:  sql.NullString{String: c.Subject, Valid: true},
		})

	case resolveRefreshIdentity:
		return s.usersService.LinkOIDCIdentity(ctx, dbgen.UsersServiceLinkOIDCIdentityParams{
			ID:           byIdentity.ID,
			OidcProvider: sql.NullString{String: providerName, Valid: true},
			OidcSubject:  sql.NullString{String: c.Subject, Valid: true},
			Name:         sql.NullString{String: c.Name, Valid: true},
			Email:        sql.NullString{String: c.Email, Valid: true},
		})

	case resolveLinkByEmail:
		if !c.EmailVerified {
			return dbgen.User{}, ErrEmailNotVerified
		}
		return s.usersService.LinkOIDCIdentity(ctx, dbgen.UsersServiceLinkOIDCIdentityParams{
			ID:           byEmail.ID,
			OidcProvider: sql.NullString{String: providerName, Valid: true},
			OidcSubject:  sql.NullString{String: c.Subject, Valid: true},
			Name:         sql.NullString{String: c.Name, Valid: true},
			Email:        sql.NullString{String: c.Email, Valid: true},
		})

	default:
		return dbgen.User{}, ErrIdentityNotRecognized
	}
}

type resolution int

const (
	resolveReject resolution = iota
	resolveCreateFirstUser
	resolveRefreshIdentity
	resolveLinkByEmail
)

// decideResolution is the pure decision logic behind HandleCallback, kept
// separate so it can be unit tested without a database. byIdentity and
// byEmail are the (at most one row each) lookups already performed by the
// caller; either may be nil.
func decideResolution(usersQty int64, byIdentity, byEmail *dbgen.User) resolution {
	if usersQty == 0 {
		return resolveCreateFirstUser
	}
	if byIdentity != nil {
		return resolveRefreshIdentity
	}
	if byEmail != nil && !users.IsOIDCUser(*byEmail) {
		return resolveLinkByEmail
	}
	return resolveReject
}
