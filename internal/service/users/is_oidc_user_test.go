package users

import (
	"database/sql"
	"testing"

	"github.com/eduardolat/pgbackweb/internal/database/dbgen"
)

func TestIsOIDCUser(t *testing.T) {
	t.Helper()

	tests := []struct {
		name     string
		user     dbgen.User
		expected bool
	}{
		{
			name: "both oidc fields set",
			user: dbgen.User{
				OidcProvider: sql.NullString{String: "google", Valid: true},
				OidcSubject:  sql.NullString{String: "sub-123", Valid: true},
			},
			expected: true,
		},
		{
			name:     "neither oidc field set",
			user:     dbgen.User{},
			expected: false,
		},
		{
			name: "only provider set",
			user: dbgen.User{
				OidcProvider: sql.NullString{String: "google", Valid: true},
			},
			expected: false,
		},
		{
			name: "only subject set",
			user: dbgen.User{
				OidcSubject: sql.NullString{String: "sub-123", Valid: true},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsOIDCUser(tt.user)
			if result != tt.expected {
				t.Errorf("IsOIDCUser(%+v) = %v, want %v", tt.user, result, tt.expected)
			}
		})
	}
}
