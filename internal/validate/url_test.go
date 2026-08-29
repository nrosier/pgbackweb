package validate

import "testing"

func TestURL(t *testing.T) {
	t.Helper()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid https url",
			input:    "https://example.com",
			expected: true,
		},
		{
			name:     "valid http url with port and path",
			input:    "http://localhost:8080/auth/oidc/callback",
			expected: true,
		},
		{
			name:     "valid url with subpath prefix",
			input:    "https://example.com/pgbackweb/auth/oidc/callback",
			expected: true,
		},
		{
			name:     "invalid - empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "invalid - no scheme",
			input:    "example.com",
			expected: false,
		},
		{
			name:     "invalid - non-http scheme",
			input:    "ftp://example.com",
			expected: false,
		},
		{
			name:     "invalid - no host",
			input:    "https://",
			expected: false,
		},
		{
			name:     "invalid - malformed",
			input:    "https://ex ample.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := URL(tt.input)
			if result != tt.expected {
				t.Errorf("URL(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
