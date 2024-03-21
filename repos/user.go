package repos

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/pquerna/otp"
)

type UserModel struct {
	BaseModel
	Name           string
	Email          string
	EmailConfirmed bool
	OTPActive      bool
	OTPKey         *otp.Key
	PasswordHash   []byte
}

type UserRepository interface {
	Find(ctx context.Context, id ulid.ULID) (*UserModel, error)
	FindByEmail(ctx context.Context, email string) (*UserModel, error)
	GetPasswordHash(ctx context.Context, userID ulid.ULID) ([]byte, error)
	GetOTP(ctx context.Context, userID ulid.ULID) (active bool, key *otp.Key, err error)
	Create(ctx context.Context, name, email string, passwordHash []byte) (*UserModel, error)
	UpdateName(ctx context.Context, id ulid.ULID, name string) error
	UpdateEmailConfirmed(ctx context.Context, id ulid.ULID, confirmed bool) error
	UpdateOTP(ctx context.Context, id ulid.ULID, active bool, otpKey *otp.Key) error
	CreateChangeEmailRequest(ctx context.Context, userID ulid.ULID, newEmail string, tokenHash []byte, lifetime time.Duration) error
	UpdateEmail(ctx context.Context, changeTokenHash []byte) (string, error)
	Delete(ctx context.Context, id ulid.ULID) error
}
