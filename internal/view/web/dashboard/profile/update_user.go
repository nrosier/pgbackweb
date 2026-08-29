package profile

import (
	"database/sql"

	"github.com/eduardolat/pgbackweb/internal/database/dbgen"
	"github.com/eduardolat/pgbackweb/internal/service/users"
	"github.com/eduardolat/pgbackweb/internal/util/pathutil"
	"github.com/eduardolat/pgbackweb/internal/validate"
	"github.com/eduardolat/pgbackweb/internal/view/reqctx"
	"github.com/eduardolat/pgbackweb/internal/view/web/component"
	"github.com/eduardolat/pgbackweb/internal/view/web/respondhtmx"
	"github.com/labstack/echo/v4"
	nodx "github.com/nodxdev/nodxgo"
	htmx "github.com/nodxdev/nodxgo-htmx"
	lucide "github.com/nodxdev/nodxgo-lucide"
)

func (h *handlers) updateUserHandler(c echo.Context) error {
	reqCtx := reqctx.GetCtx(c)
	ctx := c.Request().Context()

	var formData struct {
		Name                 string `form:"name" validate:"required"`
		Email                string `form:"email" validate:"required,email"`
		Password             string `form:"password" validate:"omitempty,min=6,max=50"`
		PasswordConfirmation string `form:"password_confirmation" validate:"omitempty,eqfield=Password"`
	}
	if err := c.Bind(&formData); err != nil {
		return respondhtmx.ToastError(c, err.Error())
	}
	if err := validate.Struct(&formData); err != nil {
		return respondhtmx.ToastError(c, err.Error())
	}

	params := dbgen.UsersServiceUpdateUserParams{
		ID:       reqCtx.User.ID,
		Name:     sql.NullString{String: formData.Name, Valid: true},
		Email:    sql.NullString{String: formData.Email, Valid: true},
		Password: sql.NullString{String: formData.Password, Valid: formData.Password != ""},
	}

	// Name and email are managed by the identity provider and refreshed on
	// every OIDC login, so client-submitted values for them are ignored
	// here regardless of what the (readonly) form fields posted.
	if users.IsOIDCUser(reqCtx.User) {
		params.Name = sql.NullString{Valid: false}
		params.Email = sql.NullString{Valid: false}
	}

	_, err := h.servs.UsersService.UpdateUser(ctx, params)
	if err != nil {
		return respondhtmx.ToastError(c, err.Error())
	}

	return respondhtmx.ToastSuccess(c, "Profile updated")
}

func updateUserForm(user dbgen.User) nodx.Node {
	isOIDCUser := users.IsOIDCUser(user)

	nameHelpText := ""
	emailHelpText := ""
	if isOIDCUser {
		nameHelpText = "Managed by your identity provider, updated on every SSO login"
		emailHelpText = nameHelpText
	}

	return component.CardBox(component.CardBoxParams{
		Children: []nodx.Node{
			nodx.FormEl(
				htmx.HxPost(pathutil.BuildPath("/dashboard/profile")),
				htmx.HxDisabledELT("find button"),
				nodx.Class("space-y-2"),

				component.H2Text("Update profile"),

				component.InputControl(component.InputControlParams{
					Name:         "name",
					Label:        "Full name",
					Placeholder:  "Your full name",
					Required:     true,
					Type:         component.InputTypeText,
					AutoComplete: "name",
					HelpText:     nameHelpText,
					Children: []nodx.Node{
						nodx.Value(user.Name),
						nodx.If(isOIDCUser, nodx.Readonly("")),
					},
				}),

				component.InputControl(component.InputControlParams{
					Name:         "email",
					Label:        "Email",
					Placeholder:  "Your email",
					Required:     true,
					AutoComplete: "email",
					Type:         component.InputTypeEmail,
					HelpText:     emailHelpText,
					Children: []nodx.Node{
						nodx.Value(user.Email),
						nodx.If(isOIDCUser, nodx.Readonly("")),
					},
				}),

				component.InputControl(component.InputControlParams{
					Name:         "password",
					Label:        "Change password",
					Placeholder:  "New password",
					AutoComplete: "new-password",
					Type:         component.InputTypePassword,
					HelpText:     "Leave empty to keep your current password",
				}),

				component.InputControl(component.InputControlParams{
					Name:         "password_confirmation",
					Label:        "Confirm password",
					Placeholder:  "Confirm new password",
					AutoComplete: "new-password",
					Type:         component.InputTypePassword,
				}),

				nodx.Div(
					nodx.Class("flex justify-end items-center space-x-2 pt-2"),
					component.HxLoadingMd(),
					nodx.Button(
						nodx.Class("btn btn-primary"),
						nodx.Type("submit"),
						component.SpanText("Save changes"),
						lucide.Save(),
					),
				),
			),
		},
	})
}
