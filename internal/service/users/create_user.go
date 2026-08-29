package users

import (
	"context"

	"github.com/eduardolat/pgbackweb/internal/database/dbgen"
	"github.com/eduardolat/pgbackweb/internal/util/cryptoutil"
)

func (s *Service) CreateUser(
	ctx context.Context, params dbgen.UsersServiceCreateUserParams,
) (dbgen.User, error) {
	if params.Password.Valid {
		hash, err := cryptoutil.CreateBcryptHash(params.Password.String)
		if err != nil {
			return dbgen.User{}, err
		}
		params.Password.String = hash
	}

	return s.dbgen.UsersServiceCreateUser(ctx, params)
}
