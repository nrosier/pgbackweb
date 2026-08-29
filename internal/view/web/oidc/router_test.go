// Package oidc_test drives a real HTTP login -> callback round trip
// against a genuine local OIDC provider (mockoidc), exercising the actual
// go-oidc/oauth2 wiring (discovery, scopes, verifier config, claim field
// names) that the pure decideResolution unit test in the oidc service
// package can't reach.
//
// It has to live in an external test package: internal/view (which this
// test imports to get a fully-wired app) transitively imports back into
// this package via auth.MountRouter, so a same-package test would create
// an import cycle.
package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/eduardolat/pgbackweb/internal/config"
	"github.com/eduardolat/pgbackweb/internal/cron"
	"github.com/eduardolat/pgbackweb/internal/database"
	"github.com/eduardolat/pgbackweb/internal/database/dbgen"
	"github.com/eduardolat/pgbackweb/internal/integration"
	"github.com/eduardolat/pgbackweb/internal/service"
	"github.com/eduardolat/pgbackweb/internal/service/users"
	"github.com/eduardolat/pgbackweb/internal/view"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/require"
)

// TestOIDCLoginRoundTrip runs against whatever database PBW_POSTGRES_CONN_STRING
// points at (the devcontainer's Postgres in practice), inside a transaction
// that is always rolled back, so it never leaves data behind and adapts to
// whatever state that database is already in: a fresh install (no users
// yet) exercises the create-first-user path, an existing install exercises
// linking an existing user by verified email.
func TestOIDCLoginRoundTrip(t *testing.T) {
	connStr := os.Getenv("PBW_POSTGRES_CONN_STRING")
	if connStr == "" {
		t.Skip("PBW_POSTGRES_CONN_STRING not set, skipping OIDC round-trip test")
	}

	idp, err := mockoidc.Run()
	require.NoError(t, err)
	defer func() { _ = idp.Shutdown() }()

	// The app needs its redirect_uri (which depends on this server's own
	// URL) before it can be built, but the server needs a handler before
	// it can start. Break the cycle with a placeholder that forwards to
	// whatever handler is installed once the real app exists.
	var appHandler http.Handler
	pbwServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appHandler.ServeHTTP(w, r)
	}))
	defer pbwServer.Close()

	idpCfg := idp.Config()
	env := config.Env{
		PBW_ENCRYPTION_KEY:       "test-encryption-key-for-oidc-round-trip",
		PBW_POSTGRES_CONN_STRING: connStr,
		PBW_OIDC_ENABLED:         true,
		PBW_OIDC_ISSUER_URL:      idpCfg.Issuer,
		PBW_OIDC_CLIENT_ID:       idpCfg.ClientID,
		PBW_OIDC_CLIENT_SECRET:   idpCfg.ClientSecret,
		PBW_OIDC_REDIRECT_URL:    pbwServer.URL + "/auth/oidc/callback",
	}

	db := database.Connect(env)
	defer db.Close()

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	dbg := dbgen.New(tx)

	cr, err := cron.New()
	require.NoError(t, err)
	ints := integration.New()

	servs, err := service.New(env, dbg, cr, ints)
	require.NoError(t, err)

	app := echo.New()
	view.MountRouter(app, servs)
	appHandler = app

	usersQty, err := servs.UsersService.GetUsersQty(ctx)
	require.NoError(t, err)

	hadExistingUser := usersQty > 0
	var wantEmail string
	var existingUserID uuid.UUID
	if hadExistingUser {
		row := tx.QueryRowContext(ctx, "SELECT id, email FROM users LIMIT 1")
		require.NoError(t, row.Scan(&existingUserID, &wantEmail))
	} else {
		wantEmail = fmt.Sprintf("oidc-roundtrip-%s@example.com", uuid.NewString())
	}

	idp.QueueUser(&mockoidc.MockUser{
		Subject:       uuid.NewString(),
		Email:         wantEmail,
		EmailVerified: true,
	})

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: our own login endpoint sets the CSRF state cookie and
	// redirects to the identity provider's authorization endpoint.
	loginResp, err := client.Get(pbwServer.URL + "/auth/oidc/login")
	require.NoError(t, err)
	defer loginResp.Body.Close()
	require.Equal(t, http.StatusFound, loginResp.StatusCode)

	authURL := loginResp.Header.Get("Location")
	require.NotEmpty(t, authURL)

	var stateCookie *http.Cookie
	for _, ck := range loginResp.Cookies() {
		if ck.Name == "pbw_oidc_state" {
			stateCookie = ck
		}
	}
	require.NotNil(t, stateCookie, "expected the login redirect to set a state cookie")

	// Step 2: the identity provider "authenticates" the queued user
	// immediately and redirects back to our redirect_uri with a code.
	authReq, err := http.NewRequest(http.MethodGet, authURL, nil)
	require.NoError(t, err)
	idpResp, err := client.Do(authReq)
	require.NoError(t, err)
	defer idpResp.Body.Close()
	require.Equal(t, http.StatusFound, idpResp.StatusCode)

	callbackURL, err := url.Parse(idpResp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, stateCookie.Value, callbackURL.Query().Get("state"))
	require.NotEmpty(t, callbackURL.Query().Get("code"))

	// Step 3: follow the identity provider's redirect back to our own
	// callback, carrying the state cookie the login step set.
	callbackReq, err := http.NewRequest(http.MethodGet, callbackURL.String(), nil)
	require.NoError(t, err)
	callbackReq.AddCookie(stateCookie)
	callbackResp, err := client.Do(callbackReq)
	require.NoError(t, err)
	defer callbackResp.Body.Close()
	require.Equal(t, http.StatusFound, callbackResp.StatusCode)
	require.Equal(t, "/dashboard", callbackResp.Header.Get("Location"))

	var sessionCookie *http.Cookie
	for _, ck := range callbackResp.Cookies() {
		if ck.Name == "pbw_session" {
			sessionCookie = ck
		}
	}
	require.NotNil(t, sessionCookie, "expected a successful login to set a session cookie")
	require.NotEmpty(t, sessionCookie.Value)

	user, err := servs.UsersService.GetUserByEmail(ctx, wantEmail)
	require.NoError(t, err)
	require.True(t, users.IsOIDCUser(user))

	if hadExistingUser {
		require.Equal(t, existingUserID, user.ID)
	} else {
		require.Equal(t, strings.SplitN(wantEmail, "@", 2)[0], user.Name)
	}
}
