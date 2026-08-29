package validate

import "net/url"

// URL validates that a string is a well-formed absolute HTTP(S) URL.
//
// Valid URLs:
// - Must parse successfully
// - Must have a scheme of http or https
// - Must have a non-empty host
//
// Examples:
// - "https://example.com" -> true
// - "http://localhost:8080/callback" -> true
// - "example.com" -> false (no scheme)
// - "ftp://example.com" -> false (not http/https)
// - "" -> false
func URL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	if parsed.Host == "" {
		return false
	}

	return true
}
