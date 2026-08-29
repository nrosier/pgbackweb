-- name: UsersServiceLinkOIDCIdentity :one
UPDATE users
SET
  oidc_provider = @oidc_provider,
  oidc_subject = @oidc_subject,
  name = COALESCE(sqlc.narg('name'), name),
  email = lower(COALESCE(sqlc.narg('email'), email))
WHERE id = @id
RETURNING *;
