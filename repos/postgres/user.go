package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/oklog/ulid/v2"
	"github.com/pquerna/otp"

	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/repos/postgres/db"
)

type userRepository struct {
	db queryStore
}

func (db *DB) NewUserRepository() repos.UserRepository {
	return &userRepository{
		db: db.db,
	}
}

func repoUsers(users []db.User) ([]*repos.UserModel, error) {
	repoUsers := make([]*repos.UserModel, len(users))
	for i, u := range users {
		user, err := repoUser(u)
		if err != nil {
			return nil, err
		}
		repoUsers[i] = user
	}
	return repoUsers, nil
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
		Admin:          user.Admin,
	}, nil
}

func repoPasskey(passkey db.Passkey) (*repos.Passkey, error) {
	id, err := ulid.Parse(passkey.ID)
	if err != nil {
		return nil, err
	}
	userID, err := ulid.Parse(passkey.UserID)
	if err != nil {
		return nil, err
	}
	var credential webauthn.Credential
	err = json.Unmarshal(passkey.Credential, &credential)
	if err != nil {
		return nil, err
	}
	return &repos.Passkey{
		BaseModel: repos.BaseModel{
			ID:        id,
			CreatedAt: time.Unix(passkey.CreatedAt, 0),
		},
		Name:       passkey.Name,
		UserID:     userID,
		Credential: credential,
	}, nil
}

func (u *userRepository) Find(ctx context.Context, id ulid.ULID) (*repos.UserModel, error) {
	user, err := u.db.FindUser(ctx, id.String())
	if err != nil {
		return nil, repoErr("find user: %w", err)
	}
	return repoUser(user)
}

func (u *userRepository) FindAll(ctx context.Context) ([]*repos.UserModel, error) {
	users, err := u.db.FindUsers(ctx)
	if err != nil {
		return nil, repoErr("find all users: %w", err)
	}
	return repoUsers(users)
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
		Now: pgtype.Int8{
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
	var result pgconn.CommandTag
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
		NewEmail: pgtype.Text{
			String: newEmail,
			Valid:  true,
		},
		NewEmailToken: tokenHash,
		NewEmailExpires: pgtype.Int8{
			Int64: time.Now().Add(lifetime).Unix(),
			Valid: true,
		},
	})
	return repoErrResult("create change email request: %w", res, err)
}

func (u *userRepository) UpdateEmail(ctx context.Context, changeTokenHash []byte) (string, error) {
	email, err := u.db.UpdateEmail(ctx, db.UpdateEmailParams{
		NewEmailToken: changeTokenHash,
		Now: pgtype.Int8{
			Int64: time.Now().Unix(),
			Valid: true,
		},
	})
	return email, repoErr("create change email request: %w", err)
}

func (u *userRepository) CreateRecoveryCodes(ctx context.Context, userID ulid.ULID, codeHashes [][]byte) error {
	tx, err := u.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
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
	return tx.Commit(ctx)
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

func (u *userRepository) CreateRemember2FAToken(ctx context.Context, userID ulid.ULID, codeHash []byte, lifetime time.Duration) error {
	err := u.db.CreateRemember2FAToken(ctx, db.CreateRemember2FATokenParams{
		CreatedAt: time.Now().Unix(),
		UserID:    userID.String(),
		CodeHash:  codeHash,
		Expires:   time.Now().Add(lifetime).Unix(),
	})
	return repoErr("create remember 2fa token: %w", err)
}

func (u *userRepository) DeleteRemember2FAToken(ctx context.Context, userID ulid.ULID, codeHash []byte) error {
	res, err := u.db.DeleteRemember2FAToken(ctx, db.DeleteRemember2FATokenParams{
		UserID:   userID.String(),
		CodeHash: codeHash,
	})
	return repoErrResult("delete remember 2fa token: %w", res, err)
}

func (u *userRepository) DeleteRemember2FATokens(ctx context.Context, userID ulid.ULID) error {
	res, err := u.db.DeleteRemember2FATokens(ctx, db.DeleteRemember2FATokensParams{
		UserID: userID.String(),
		Now:    time.Now().Unix(),
	})
	return repoErrResult("delete remember 2fa tokens: %w", res, err)
}

func (u *userRepository) CheckRemember2FAToken(ctx context.Context, userID ulid.ULID, codeHash []byte) (bool, error) {
	exists, err := u.db.CheckRemember2FAToken(ctx, db.CheckRemember2FATokenParams{
		UserID:   userID.String(),
		CodeHash: codeHash,
		Now:      time.Now().Unix(),
	})
	if err != nil {
		return false, repoErr("check remember 2fa token: %w", err)
	}
	return exists, nil
}

func (u *userRepository) CreatePasskey(ctx context.Context, userID ulid.ULID, name string, credential webauthn.Credential) error {
	cred, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("encode passkey credential: %w", err)
	}
	res, err := u.db.CreatePasskey(ctx, db.CreatePasskeyParams{
		ID:         ulid.Make().String(),
		CreatedAt:  time.Now().Unix(),
		CredID:     credential.ID,
		Name:       name,
		UserID:     userID.String(),
		Credential: cred,
	})
	return repoErrResult("create passkey: %w", res, err)
}

func (u *userRepository) GetPasskeys(ctx context.Context, userID ulid.ULID) ([]*repos.Passkey, error) {
	passkeys, err := u.db.FindPasskeys(ctx, userID.String())
	if err != nil {
		return nil, repoErr("get passkeys: %w", err)
	}
	repoPasskeys := make([]*repos.Passkey, len(passkeys))
	for i, p := range passkeys {
		rp, err := repoPasskey(p)
		if err != nil {
			return nil, fmt.Errorf("get passkey: %w", err)
		}
		repoPasskeys[i] = rp
	}
	return repoPasskeys, nil
}

func (u *userRepository) GetPasskey(ctx context.Context, userID, id ulid.ULID) (*repos.Passkey, error) {
	passkey, err := u.db.FindPasskey(ctx, db.FindPasskeyParams{
		UserID: userID.String(),
		ID:     id.String(),
	})
	if err != nil {
		return nil, repoErr("get passkey: %w", err)
	}
	return repoPasskey(passkey)
}

func (u *userRepository) UpdatePasskeyCredential(ctx context.Context, userID ulid.ULID, credential webauthn.Credential) error {
	cred, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("encode passkey credential: %w", err)
	}
	res, err := u.db.UpdatePasskeyCredential(ctx, db.UpdatePasskeyCredentialParams{
		UserID:     userID.String(),
		CredID:     credential.ID,
		Credential: cred,
	})
	return repoErrResult("update passkey credential: %w", res, err)
}

func (u *userRepository) UpdatePasskey(ctx context.Context, userID, id ulid.ULID, name string) error {
	res, err := u.db.UpdatePasskey(ctx, db.UpdatePasskeyParams{
		Name:   name,
		UserID: userID.String(),
		ID:     id.String(),
	})
	return repoErrResult("update passkey: %w", res, err)
}

func (u *userRepository) DeletePasskey(ctx context.Context, userID, id ulid.ULID) error {
	res, err := u.db.DeletePasskey(ctx, db.DeletePasskeyParams{
		UserID: userID.String(),
		ID:     id.String(),
	})
	return repoErrResult("delete passkey: %w", res, err)
}

func (u *userRepository) UpdateAdminStatus(ctx context.Context, userID ulid.ULID, isAdmin bool) error {
	res, err := u.db.UpdateAdminStatus(ctx, db.UpdateAdminStatusParams{
		ID:    userID.String(),
		Admin: isAdmin,
	})
	return repoErrResult("update admin status: %w", res, err)
}

func (u *userRepository) Delete(ctx context.Context, id ulid.ULID) error {
	result, err := u.db.DeleteUser(ctx, id.String())
	return repoErrResult("delete user: %w", result, err)
}
