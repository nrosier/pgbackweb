package echoutil

import "github.com/labstack/echo/v4"

// IsSecureRequest reports whether the request was received over a direct
// TLS connection. This codebase has no reverse-proxy-trust configuration
// (no X-Forwarded-Proto handling), so direct TLS is the only reliable
// signal available; deployments terminating TLS at a reverse proxy will
// see this return false and should terminate TLS in the Go process itself
// if they need Secure cookies.
func IsSecureRequest(c echo.Context) bool {
	return c.Request().TLS != nil
}
