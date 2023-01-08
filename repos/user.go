package repos

import "context"

type UserModel struct {
	ID             string `db:"id"`
	Name           string `db:"name"`
	Email          string `db:"email"`
	EmailConfirmed bool   `db:"email_confirmed"`
	PasswordHash   []byte `db:"password_hash"`
}

type UserRepository interface {
	BeginTransaction(ctx context.Context) (UserTransaction, error)
	Find(ctx context.Context, id string) (*UserModel, error)
	FindByEmail(ctx context.Context, email string) (*UserModel, error)
	GetPasswordHash(ctx context.Context, userID string) ([]byte, error)
}

type UserTransaction interface {
	Transaction

	Create(name, email string, passwordHash []byte) (*UserModel, error)
	UpdateEmailConfirmed(id string, confirmed bool) error
	Delete(id string) error
}
