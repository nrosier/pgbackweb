package users

import (
	"context"
	"database/sql"
	"errors"

	"github.com/eduardolat/pgbackweb/internal/database/dbgen"
)

// GetUserByOIDCIdentity looks up the user linked to the given OIDC
// provider+subject pair. Returns (false, ..., nil) when no user is linked
// to that identity yet.
func (s *Service) GetUserByOIDCIdentity(
	ctx context.Context, provider, subject string,
) (bool, dbgen.User, error) {
	user, err := s.dbgen.UsersServiceGetUserByOIDCIdentity(
		ctx, dbgen.UsersServiceGetUserByOIDCIdentityParams{
			OidcProvider: sql.NullString{String: provider, Valid: true},
			OidcSubject:  sql.NullString{String: subject, Valid: true},
		},
	)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return false, user, nil
	}
	if err != nil {
		return false, user, err
	}

	return true, user, nil
}
