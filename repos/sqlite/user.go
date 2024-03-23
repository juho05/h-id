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
	db    *db.Queries
	rawDB *sql.DB
}

func (db *DB) NewUserRepository() repos.UserRepository {
	return &userRepository{
		db:    db.db,
		rawDB: db.rawDB,
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

func (u *userRepository) FindByChangeEmailToken(ctx context.Context, tokenHash []byte) (*repos.UserModel, error) {
	user, err := u.db.FindUserByChangeEmailToken(ctx, db.FindUserByChangeEmailTokenParams{
		NewEmailToken: tokenHash,
		Now: sql.NullInt64{
			Int64: time.Now().Unix(),
			Valid: true,
		},
	})
	if err != nil {
		return nil, repoErr("find user by change email token: %w", err)
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

func (u *userRepository) UpdatePassword(ctx context.Context, id ulid.ULID, passwordHash []byte) error {
	result, err := u.db.UpdatePassword(ctx, db.UpdatePasswordParams{
		ID:           id.String(),
		PasswordHash: passwordHash,
	})
	return repoErrResult("update user password: %w", result, err)
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

func (u *userRepository) CreateChangeEmailRequest(ctx context.Context, userID ulid.ULID, newEmail string, tokenHash []byte, lifetime time.Duration) error {
	res, err := u.db.CreateChangeEmailRequest(ctx, db.CreateChangeEmailRequestParams{
		ID: userID.String(),
		NewEmail: sql.NullString{
			String: newEmail,
			Valid:  true,
		},
		NewEmailToken: tokenHash,
		NewEmailExpires: sql.NullInt64{
			Int64: time.Now().Add(lifetime).Unix(),
			Valid: true,
		},
	})
	return repoErrResult("create change email request: %w", res, err)
}

func (u *userRepository) UpdateEmail(ctx context.Context, changeTokenHash []byte) (string, error) {
	email, err := u.db.UpdateEmail(ctx, db.UpdateEmailParams{
		NewEmailToken: changeTokenHash,
		Now: sql.NullInt64{
			Int64: time.Now().Unix(),
			Valid: true,
		},
	})
	return email, repoErr("create change email request: %w", err)
}

func (u *userRepository) CreateRecoveryCodes(ctx context.Context, userID ulid.ULID, codeHashes [][]byte) error {
	sqlTx, err := u.rawDB.Begin()
	if err != nil {
		return err
	}
	defer sqlTx.Rollback()
	tx := u.db.WithTx(sqlTx)
	for _, c := range codeHashes {
		err = tx.CreateRecoveryCode(ctx, db.CreateRecoveryCodeParams{
			CreatedAt: time.Now().Unix(),
			UserID:    userID.String(),
			CodeHash:  c,
		})
		if err != nil {
			return err
		}
	}
	return sqlTx.Commit()
}

func (u *userRepository) CountRecoveryCodes(ctx context.Context, userID ulid.ULID) (int, error) {
	count, err := u.db.CountRecoveryCodes(ctx, userID.String())
	return int(count), err
}

func (u *userRepository) DeleteRecoveryCode(ctx context.Context, userID ulid.ULID, codeHash []byte) error {
	res, err := u.db.DeleteRecoveryCode(ctx, db.DeleteRecoveryCodeParams{
		UserID:   userID.String(),
		CodeHash: codeHash,
	})
	return repoErrResult("delete recovery code: %w", res, err)
}

func (u *userRepository) DeleteRecoveryCodes(ctx context.Context, userID ulid.ULID) error {
	res, err := u.db.DeleteRecoveryCodes(ctx, userID.String())
	return repoErrResult("delete recovery codes: %w", res, err)
}

func (u *userRepository) Delete(ctx context.Context, id ulid.ULID) error {
	result, err := u.db.DeleteUser(ctx, id.String())
	return repoErrResult("delete user: %w", result, err)
}
