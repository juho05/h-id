package repos

import (
	"context"

	"github.com/oklog/ulid/v2"
)

type UserModel struct {
	BaseModel
	Name           string
	Email          string
	EmailConfirmed bool
	PasswordHash   []byte
}

type UserRepository interface {
	Find(ctx context.Context, id ulid.ULID) (*UserModel, error)
	FindByEmail(ctx context.Context, email string) (*UserModel, error)
	GetPasswordHash(ctx context.Context, userID ulid.ULID) ([]byte, error)
	Create(ctx context.Context, name, email string, passwordHash []byte) (*UserModel, error)
	UpdateName(ctx context.Context, id ulid.ULID, name string) error
	UpdateEmailConfirmed(ctx context.Context, id ulid.ULID, confirmed bool) error
	Delete(ctx context.Context, id ulid.ULID) error
}
