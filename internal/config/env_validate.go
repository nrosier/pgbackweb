package config

import (
	"fmt"
	"net/url"

	"github.com/eduardolat/pgbackweb/internal/validate"
)

// validateEnv runs additional validations on the environment variables.
func validateEnv(env Env) error {
	if !validate.ListenHost(env.PBW_LISTEN_HOST) {
		return fmt.Errorf("invalid listen address %s", env.PBW_LISTEN_HOST)
	}

	if !validate.Port(env.PBW_LISTEN_PORT) {
		return fmt.Errorf("invalid listen port %s, valid values are 1-65535", env.PBW_LISTEN_PORT)
	}

	if !validate.PathPrefix(env.PBW_PATH_PREFIX) {
		return fmt.Errorf("invalid path prefix %s, must start with / and not end with / (or be empty)", env.PBW_PATH_PREFIX)
	}

	if env.PBW_OIDC_ENABLED {
		if !validate.URL(env.PBW_OIDC_ISSUER_URL) {
			return fmt.Errorf("invalid PBW_OIDC_ISSUER_URL %s, must be a valid http(s) URL", env.PBW_OIDC_ISSUER_URL)
		}

		if env.PBW_OIDC_CLIENT_ID == "" {
			return fmt.Errorf("PBW_OIDC_CLIENT_ID is required when PBW_OIDC_ENABLED is true")
		}

		if env.PBW_OIDC_CLIENT_SECRET == "" {
			return fmt.Errorf("PBW_OIDC_CLIENT_SECRET is required when PBW_OIDC_ENABLED is true")
		}

		if !validate.URL(env.PBW_OIDC_REDIRECT_URL) {
			return fmt.Errorf("invalid PBW_OIDC_REDIRECT_URL %s, must be a valid http(s) URL", env.PBW_OIDC_REDIRECT_URL)
		}

		expectedPath := env.PBW_PATH_PREFIX + "/auth/oidc/callback"
		redirectURL, err := url.Parse(env.PBW_OIDC_REDIRECT_URL)
		if err != nil || redirectURL.Path != expectedPath {
			return fmt.Errorf(
				"PBW_OIDC_REDIRECT_URL path must be %s (got %s), did you forget PBW_PATH_PREFIX?",
				expectedPath, env.PBW_OIDC_REDIRECT_URL,
			)
		}
	}

	return nil
}
