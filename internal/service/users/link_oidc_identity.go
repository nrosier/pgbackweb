package users

import (
	"context"

	"github.com/eduardolat/pgbackweb/internal/database/dbgen"
)

// LinkOIDCIdentity attaches an OIDC provider+subject pair to an existing
// user, refreshing their name/email from the identity provider's claims.
// It is idempotent: calling it again with the same identity for the same
// user simply refreshes name/email.
func (s *Service) LinkOIDCIdentity(
	ctx context.Context, params dbgen.UsersServiceLinkOIDCIdentityParams,
) (dbgen.User, error) {
	return s.dbgen.UsersServiceLinkOIDCIdentity(ctx, params)
}
