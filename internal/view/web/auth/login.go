package auth

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/eduardolat/pgbackweb/internal/logger"
	"github.com/eduardolat/pgbackweb/internal/util/echoutil"
	"github.com/eduardolat/pgbackweb/internal/util/pathutil"
	"github.com/eduardolat/pgbackweb/internal/validate"
	"github.com/eduardolat/pgbackweb/internal/view/web/component"
	"github.com/eduardolat/pgbackweb/internal/view/web/layout"
	"github.com/eduardolat/pgbackweb/internal/view/web/oidc"
	"github.com/eduardolat/pgbackweb/internal/view/web/respondhtmx"
	"github.com/labstack/echo/v4"
	nodx "github.com/nodxdev/nodxgo"
	htmx "github.com/nodxdev/nodxgo-htmx"
	lucide "github.com/nodxdev/nodxgo-lucide"
)

func (h *handlers) loginPageHandler(c echo.Context) error {
	ctx := c.Request().Context()

	usersQty, err := h.servs.UsersService.GetUsersQty(ctx)
	if err != nil {
		logger.Error("failed to get users qty", logger.KV{
			"ip":    c.RealIP(),
			"ua":    c.Request().UserAgent(),
			"error": err,
		})
		return c.String(http.StatusInternalServerError, "Internal server error")
	}
	if usersQty == 0 {
		return c.Redirect(http.StatusFound, pathutil.BuildPath("/auth/create-first-user"))
	}

	return echoutil.RenderNodx(c, http.StatusOK, loginPage(loginPageParams{
		OIDCEnabled: h.servs.OIDCService.IsEnabled(),
		OIDCError:   c.QueryParam("error"),
	}))
}

type loginPageParams struct {
	OIDCEnabled bool
	OIDCError   string
}

func loginPage(params loginPageParams) nodx.Node {
	content := []nodx.Node{
		component.H1Text("Login"),

		nodx.FormEl(
			htmx.HxPost(pathutil.BuildPath("/auth/login")),
			htmx.HxDisabledELT("find button"),
			nodx.Class("mt-4 space-y-2"),

			component.InputControl(component.InputControlParams{
				Name:         "email",
				Label:        "Email",
				Placeholder:  "john@example.com",
				Required:     true,
				Type:         component.InputTypeEmail,
				AutoComplete: "email",
				Children: []nodx.Node{
					nodx.Autofocus(""),
				},
			}),

			component.InputControl(component.InputControlParams{
				Name:         "password",
				Label:        "Password",
				Placeholder:  "******",
				Required:     true,
				Type:         component.InputTypePassword,
				AutoComplete: "current-password",
			}),

			nodx.Div(
				nodx.Class("pt-2 flex justify-end items-center space-x-2"),
				component.HxLoadingMd(),
				nodx.Button(
					nodx.Class("btn btn-primary"),
					nodx.Type("submit"),
					component.SpanText("Login"),
					lucide.LogIn(),
				),
			),
		),
	}

	if params.OIDCEnabled {
		content = append(content,
			nodx.Div(
				nodx.Class("divider"),
				component.SpanText("or"),
			),
			nodx.A(
				nodx.Href(pathutil.BuildPath("/auth/oidc/login")),
				nodx.Class("btn btn-outline w-full"),
				component.SpanText("Sign in with SSO"),
				lucide.KeyRound(),
			),
		)
	}

	if params.OIDCError != "" {
		content = append(content, oidcErrorScript(params.OIDCError))
	}

	return layout.Auth(layout.AuthParams{
		Title: "Login",
		Body:  content,
	})
}

// oidcErrorScript renders an inline toast for a failed OIDC login. A plain
// browser navigation to this page (which is how the OIDC callback reports
// errors) isn't an HTMX request, so respondhtmx's HX-Trigger-based toasts
// don't apply here; this mirrors the pattern in component/copy_button.go
// for injecting a small inline script. The message always comes from
// oidc.Message, a fixed lookup over known error codes, never from the raw
// query string, so there's nothing attacker-controlled to escape here —
// strconv.Quote is used anyway to keep the script well-formed regardless.
func oidcErrorScript(code string) nodx.Node {
	message := oidc.Message(code)
	rawScript := fmt.Sprintf(
		"<script>window.toaster.error(%s);</script>",
		strconv.Quote(message),
	)
	return nodx.Raw(rawScript)
}

func (h *handlers) loginHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var formData struct {
		Email    string `form:"email" validate:"required,email"`
		Password string `form:"password" validate:"required,max=50"`
	}
	if err := c.Bind(&formData); err != nil {
		return respondhtmx.ToastError(c, err.Error())
	}
	if err := validate.Struct(&formData); err != nil {
		return respondhtmx.ToastError(c, err.Error())
	}

	session, err := h.servs.AuthService.Login(
		ctx, formData.Email, formData.Password, c.RealIP(), c.Request().UserAgent(),
	)
	if err != nil {
		logger.Error("login failed", logger.KV{
			"email": formData.Email,
			"ip":    c.RealIP(),
			"ua":    c.Request().UserAgent(),
			"err":   err,
		})
		return respondhtmx.ToastError(c, "Login failed")
	}

	h.servs.AuthService.SetSessionCookie(c, session.DecryptedToken)
	return respondhtmx.Redirect(c, pathutil.BuildPath("/dashboard"))
}
