-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
  ALTER COLUMN password DROP NOT NULL,
  ADD COLUMN oidc_provider TEXT,
  ADD COLUMN oidc_subject TEXT,
  ADD CONSTRAINT users_oidc_pair_chk
    CHECK ((oidc_provider IS NULL) = (oidc_subject IS NULL)),
  ADD CONSTRAINT users_password_or_oidc_chk
    CHECK (password IS NOT NULL OR (oidc_provider IS NOT NULL AND oidc_subject IS NOT NULL));

CREATE UNIQUE INDEX users_oidc_identity_idx ON users (oidc_provider, oidc_subject)
  WHERE oidc_provider IS NOT NULL AND oidc_subject IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS users_oidc_identity_idx;

ALTER TABLE users
  DROP CONSTRAINT IF EXISTS users_password_or_oidc_chk,
  DROP CONSTRAINT IF EXISTS users_oidc_pair_chk,
  DROP COLUMN IF EXISTS oidc_subject,
  DROP COLUMN IF EXISTS oidc_provider,
  ALTER COLUMN password SET NOT NULL;
-- +goose StatementEnd
