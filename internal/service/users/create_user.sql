-- name: UsersServiceCreateUser :one
INSERT INTO users (name, email, password, oidc_provider, oidc_subject)
VALUES (@name, lower(@email), @password, @oidc_provider, @oidc_subject)
RETURNING *;
