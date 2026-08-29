package auth

import (
	"context"

	"github.com/eduardolat/pgbackweb/internal/database/dbgen"
	"github.com/google/uuid"
)

// LoginOIDC creates a session for a user that has already been
// authenticated via an OIDC identity provider. Unlike Login, it performs
// no password check, since the caller is expected to have already
// verified the user's identity via the ID token.
func (s *Service) LoginOIDC(
	ctx context.Context, user dbgen.User, ip, userAgent string,
) (dbgen.AuthServiceLoginCreateSessionRow, error) {
	session, err := s.dbgen.AuthServiceLoginCreateSession(
		ctx, dbgen.AuthServiceLoginCreateSessionParams{
			UserID:        user.ID,
			Ip:            ip,
			UserAgent:     userAgent,
			Token:         uuid.NewString(),
			EncryptionKey: s.env.PBW_ENCRYPTION_KEY,
		},
	)
	if err != nil {
		return dbgen.AuthServiceLoginCreateSessionRow{}, err
	}

	return session, nil
}
