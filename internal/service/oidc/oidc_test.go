package oidc

import (
	"database/sql"
	"testing"

	"github.com/eduardolat/pgbackweb/internal/database/dbgen"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestDecideResolution(t *testing.T) {
	linkedUser := &dbgen.User{
		ID:           uuid.New(),
		OidcProvider: sql.NullString{String: "oidc", Valid: true},
		OidcSubject:  sql.NullString{String: "some-other-subject", Valid: true},
	}
	unlinkedUser := &dbgen.User{
		ID:       uuid.New(),
		Password: sql.NullString{String: "hash", Valid: true},
	}

	tests := []struct {
		name       string
		usersQty   int64
		byIdentity *dbgen.User
		byEmail    *dbgen.User
		want       resolution
	}{
		{
			name:     "fresh install with no users creates the first one",
			usersQty: 0,
			want:     resolveCreateFirstUser,
		},
		{
			name:       "exact identity match refreshes the existing user",
			usersQty:   1,
			byIdentity: linkedUser,
			want:       resolveRefreshIdentity,
		},
		{
			name:     "unlinked local user matching email gets linked",
			usersQty: 1,
			byEmail:  unlinkedUser,
			want:     resolveLinkByEmail,
		},
		{
			name:     "no identity or email match is rejected",
			usersQty: 1,
			want:     resolveReject,
		},
		{
			name:     "email match already linked to a different identity is rejected",
			usersQty: 1,
			byEmail:  linkedUser,
			want:     resolveReject,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decideResolution(tt.usersQty, tt.byIdentity, tt.byEmail)
			assert.Equal(t, tt.want, got)
		})
	}
}
