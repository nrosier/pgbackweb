package oidc

// Fixed enum of OIDC error codes that may appear in the "error" query
// param on a redirect back to the login page. Keeping this a fixed,
// known set (rather than reflecting free text from the identity provider
// or an internal error message) avoids ever putting attacker-influenced
// content into a URL or an inline script.
const (
	ErrCodeInvalidState     = "invalid_state"
	ErrCodeNotRecognized    = "not_recognized"
	ErrCodeEmailNotVerified = "email_not_verified"
	ErrCodeCallbackFailed   = "callback_failed"
)

var errorMessages = map[string]string{
	ErrCodeInvalidState:     "Your sign-in session expired, please try again",
	ErrCodeNotRecognized:    "This identity is not recognized for this instance",
	ErrCodeEmailNotVerified: "Your identity provider account's email is not verified",
	ErrCodeCallbackFailed:   "Something went wrong signing in with SSO, please try again",
}

// Message returns the user-facing message for a known OIDC error code, or
// a generic fallback for anything else, including unrecognized codes an
// attacker might put in the query string by hand.
func Message(code string) string {
	if msg, ok := errorMessages[code]; ok {
		return msg
	}
	return "Something went wrong signing in with SSO"
}
