package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/pquerna/otp"

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
	otpKey, err := otp.NewKeyFromURL(user.OtpUrl)
	if err != nil {
		if user.OtpUrl == "" {
			otpKey = nil
		} else {
			return nil, fmt.Errorf("convert otp url in db to otp key: %w", err)
		}
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
		OTPActive:      user.OtpActive,
		OTPKey:         otpKey,
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

func (u *userRepository) GetOTP(ctx context.Context, userID ulid.ULID) (active bool, key *otp.Key, err error) {
	res, err := u.db.GetOTP(ctx, userID.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = repos.ErrNoRecord
		}
		return false, nil, fmt.Errorf("get otp: %w", err)
	}
	otpKey, err := otp.NewKeyFromURL(res.OtpUrl)
	if err != nil {
		if res.OtpUrl == "" {
			otpKey = nil
		} else {
			return false, nil, fmt.Errorf("convert otp url in db to otp key: %w", err)
		}
	}
	return res.OtpActive, otpKey, nil
}

func (u *userRepository) Create(ctx context.Context, name, email string, passwordHash []byte) (*repos.UserModel, error) {
	user, err := u.db.CreateUser(ctx, db.CreateUserParams{
		ID:             ulid.Make().String(),
		CreatedAt:      time.Now().Unix(),
		Name:           name,
		Email:          email,
		EmailConfirmed: false,
		PasswordHash:   passwordHash,
		OtpActive:      false,
		OtpUrl:         "",
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

func (u *userRepository) UpdateOTP(ctx context.Context, id ulid.ULID, active bool, otpKey *otp.Key) error {
	var result sql.Result
	var err error
	if otpKey != nil || !active {
		var otpURL string
		if otpKey != nil {
			otpURL = otpKey.URL()
		}
		result, err = u.db.UpdateOTP(ctx, db.UpdateOTPParams{
			ID:        id.String(),
			OtpActive: active,
			OtpUrl:    otpURL,
		})
	} else {
		result, err = u.db.SetOTPActive(ctx, db.SetOTPActiveParams{
			ID:        id.String(),
			OtpActive: active,
		})
	}
	return repoErrResult("update otp: %w", result, err)
}

func (u *userRepository) Delete(ctx context.Context, id ulid.ULID) error {
	result, err := u.db.DeleteUser(ctx, id.String())
	return repoErrResult("delete user: %w", result, err)
}
