package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/repos/sqlite/db"
)

type userRepository struct {
	db *db.Queries
}

func (db *DB) NewUserRepository() repos.UserRepository {
	return &userRepository{
		db: db.db,
	}
}

func repoUser(user db.User) (*repos.UserModel, error) {
	id, err := ulid.Parse(user.ID)
	if err != nil {
		return nil, err
	}
	return &repos.UserModel{
		BaseModel: repos.BaseModel{
			ID:        id,
			CreatedAt: time.Unix(user.CreatedAt, 0),
		},
		Name:           user.Name,
		Email:          user.Email,
		EmailConfirmed: user.EmailConfirmed,
		PasswordHash:   user.PasswordHash,
	}, nil
}

func (u *userRepository) Find(ctx context.Context, id ulid.ULID) (*repos.UserModel, error) {
	user, err := u.db.FindUser(ctx, id.String())
	if err != nil {
		return nil, repoErr("find user: %w", err)
	}
	return repoUser(user)
}

func (u *userRepository) FindByEmail(ctx context.Context, email string) (*repos.UserModel, error) {
	user, err := u.db.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, repoErr("find user by email: %w", err)
	}
	return repoUser(user)
}

func (u *userRepository) GetPasswordHash(ctx context.Context, userID ulid.ULID) ([]byte, error) {
	hash, err := u.db.GetUserPasswordHash(ctx, userID.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = repos.ErrNoRecord
		}
		return nil, fmt.Errorf("get password hash: %w", err)
	}
	return hash, nil
}

func (u *userRepository) Create(ctx context.Context, name, email string, passwordHash []byte) (*repos.UserModel, error) {
	user, err := u.db.CreateUser(ctx, db.CreateUserParams{
		ID:             ulid.Make().String(),
		CreatedAt:      time.Now().Unix(),
		Name:           name,
		Email:          email,
		EmailConfirmed: false,
		PasswordHash:   passwordHash,
	})
	if err != nil {
		return nil, repoErr("create user name: %w", err)
	}
	return repoUser(user)
}

func (u *userRepository) UpdateName(ctx context.Context, id ulid.ULID, name string) error {
	result, err := u.db.UpdateUserName(ctx, db.UpdateUserNameParams{
		ID:   id.String(),
		Name: name,
	})
	return repoErrResult("update user: %w", result, err)
}

func (u *userRepository) UpdateEmailConfirmed(ctx context.Context, id ulid.ULID, confirmed bool) error {
	result, err := u.db.UpdateEmailConfirmed(ctx, db.UpdateEmailConfirmedParams{
		ID:             id.String(),
		EmailConfirmed: confirmed,
	})
	return repoErrResult("update user email confirmed: %w", result, err)
}

func (u *userRepository) Delete(ctx context.Context, id ulid.ULID) error {
	result, err := u.db.DeleteUser(ctx, id.String())
	return repoErrResult("delete user: %w", result, err)
}
