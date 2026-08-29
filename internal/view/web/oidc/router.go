package oidc

import (
	"errors"
	"net/http"
	"time"

	"github.com/eduardolat/pgbackweb/internal/logger"
	"github.com/eduardolat/pgbackweb/internal/service"
	svcoidc "github.com/eduardolat/pgbackweb/internal/service/oidc"
	"github.com/eduardolat/pgbackweb/internal/util/echoutil"
	"github.com/eduardolat/pgbackweb/internal/util/pathutil"
	"github.com/eduardolat/pgbackweb/internal/view/middleware"
	"github.com/eduardolat/pgbackweb/internal/view/web/respondhtmx"
	"github.com/labstack/echo/v4"
	htmx "github.com/nodxdev/nodxgo-htmx"
)

const (
	stateCookieName          = "pbw_oidc_state"
	stateCookieMaxAgeSeconds = int((5 * time.Minute) / time.Second)
)

type handlers struct {
	servs *service.Service
}

func MountRouter(
	parent *echo.Group, mids *middleware.Middleware, servs *service.Service,
) {
	h := handlers{servs: servs}

	requireNoAuth := parent.Group("", mids.RequireNoAuth)

	rateLimit := mids.RateLimit(middleware.RateLimitConfig{
		Limit:  5,
		Period: 10 * time.Second,
	})

	requireNoAuth.GET("/login", h.oidcLoginHandler, rateLimit)
	requireNoAuth.GET("/callback", h.oidcCallbackHandler, rateLimit)
}

func (h *handlers) oidcLoginHandler(c echo.Context) error {
	if !h.servs.OIDCService.IsEnabled() {
		return c.String(http.StatusNotFound, "Not found")
	}

	state, err := h.servs.OIDCService.GenerateState()
	if err != nil {
		logger.Error("failed to generate oidc state", logger.KV{
			"ip":    c.RealIP(),
			"ua":    c.Request().UserAgent(),
			"error": err,
		})
		return c.String(http.StatusInternalServerError, "Internal server error")
	}

	setStateCookie(c, state, stateCookieMaxAgeSeconds)
	return c.Redirect(http.StatusFound, h.servs.OIDCService.GetAuthURL(state))
}

func (h *handlers) oidcCallbackHandler(c echo.Context) error {
	ctx := c.Request().Context()

	if !h.servs.OIDCService.IsEnabled() {
		return c.String(http.StatusNotFound, "Not found")
	}

	cookie, cookieErr := c.Cookie(stateCookieName)
	clearStateCookie(c)

	if cookieErr != nil || cookie.Value == "" || cookie.Value != c.QueryParam("state") {
		return h.handleOIDCError(c, ErrCodeInvalidState)
	}

	code := c.QueryParam("code")
	if code == "" {
		return h.handleOIDCError(c, ErrCodeCallbackFailed)
	}

	user, err := h.servs.OIDCService.HandleCallback(ctx, code)
	if err != nil {
		logger.Error("oidc callback failed", logger.KV{
			"ip":    c.RealIP(),
			"ua":    c.Request().UserAgent(),
			"error": err,
		})

		switch {
		case errors.Is(err, svcoidc.ErrIdentityNotRecognized):
			return h.handleOIDCError(c, ErrCodeNotRecognized)
		case errors.Is(err, svcoidc.ErrEmailNotVerified):
			return h.handleOIDCError(c, ErrCodeEmailNotVerified)
		default:
			return h.handleOIDCError(c, ErrCodeCallbackFailed)
		}
	}

	session, err := h.servs.AuthService.LoginOIDC(
		ctx, user, c.RealIP(), c.Request().UserAgent(),
	)
	if err != nil {
		logger.Error("failed to create session after oidc login", logger.KV{
			"ip":    c.RealIP(),
			"ua":    c.Request().UserAgent(),
			"error": err,
		})
		return h.handleOIDCError(c, ErrCodeCallbackFailed)
	}

	h.servs.AuthService.SetSessionCookie(c, session.DecryptedToken)
	return c.Redirect(http.StatusFound, pathutil.BuildPath("/dashboard"))
}

// handleOIDCError reports a fixed, known error code back to the user. It
// never reflects free text (an internal error message, or anything from
// the identity provider) into the redirect URL or response.
func (h *handlers) handleOIDCError(c echo.Context, code string) error {
	if htmx.ServerGetIsHtmxRequest(c.Request().Header) {
		return respondhtmx.ToastError(c, Message(code))
	}
	redirectPath := pathutil.BuildPath("/auth/login") + "?error=" + code
	return c.Redirect(http.StatusFound, redirectPath)
}

func setStateCookie(c echo.Context, value string, maxAgeSeconds int) {
	c.SetCookie(&http.Cookie{
		Name:     stateCookieName,
		Value:    value,
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   echoutil.IsSecureRequest(c),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

func clearStateCookie(c echo.Context) {
	setStateCookie(c, "", -1)
}
