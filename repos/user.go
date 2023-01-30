package repos

import (
	"context"
)

type UserModel struct {
	BaseModel
	Name           string `db:"name"`
	Email          string `db:"email"`
	EmailConfirmed bool   `db:"email_confirmed"`
	PasswordHash   []byte `db:"password_hash"`
}

type UserRepository interface {
	Find(ctx context.Context, id string) (*UserModel, error)
	FindByEmail(ctx context.Context, email string) (*UserModel, error)
	GetPasswordHash(ctx context.Context, userID string) ([]byte, error)
	Create(ctx context.Context, name, email string, passwordHash []byte) (*UserModel, error)
	Update(ctx context.Context, id, name string) error
	UpdateEmailConfirmed(ctx context.Context, id string, confirmed bool) error
	Delete(ctx context.Context, id string) error
}
