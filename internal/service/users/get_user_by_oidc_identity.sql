-- name: UsersServiceGetUserByOIDCIdentity :one
SELECT * FROM users WHERE oidc_provider = @oidc_provider AND oidc_subject = @oidc_subject;
