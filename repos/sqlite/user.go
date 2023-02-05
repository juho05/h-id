package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/Bananenpro/h-id/repos"
)

type userRepository struct {
	db *sqlx.DB
}

func (db *DB) NewUserRepository() repos.UserRepository {
	return &userRepository{
		db: db.db,
	}
}

func (u *userRepository) Find(ctx context.Context, id string) (*repos.UserModel, error) {
	var user repos.UserModel
	err := u.db.GetContext(ctx, &user, "SELECT * FROM users WHERE id = ?", id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = repos.ErrNoRecord
		}
		return nil, fmt.Errorf("find user: %w", err)
	}
	return &user, nil
}

func (u *userRepository) FindByEmail(ctx context.Context, email string) (*repos.UserModel, error) {
	var user repos.UserModel
	err := u.db.GetContext(ctx, &user, "SELECT * FROM users WHERE email = ?", email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = repos.ErrNoRecord
		}
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return &user, nil
}

func (u *userRepository) GetPasswordHash(ctx context.Context, userID string) ([]byte, error) {
	var hash []byte
	err := u.db.GetContext(ctx, &hash, "SELECT password_hash FROM users WHERE id = ?", userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = repos.ErrNoRecord
		}
		return nil, fmt.Errorf("get password hash: %w", err)
	}
	return hash, nil
}

func (u *userRepository) Create(ctx context.Context, name, email string, passwordHash []byte) (*repos.UserModel, error) {
	user := &repos.UserModel{
		BaseModel:      newBase(),
		Name:           name,
		Email:          email,
		EmailConfirmed: false,
		PasswordHash:   passwordHash,
	}
	_, err := u.db.ExecContext(ctx, "INSERT INTO users (id, created_at, name, email, email_confirmed, password_hash) VALUES (?, ?, ?, ?, ?, ?)", user.ID, user.CreatedAt, user.Name, user.Email, user.EmailConfirmed, user.PasswordHash)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE && strings.Contains(sqliteErr.Error(), "email") {
			err = repos.ErrDuplicateEmail
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (u *userRepository) Update(ctx context.Context, id, name string) error {
	result, err := u.db.ExecContext(ctx, "UPDATE users SET name = ? WHERE id = ?", name, id)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("update user: %w", repos.ErrNoRecord)
	}
	return nil
}

func (u *userRepository) UpdateEmailConfirmed(ctx context.Context, id string, confirmed bool) error {
	result, err := u.db.ExecContext(ctx, "UPDATE users SET email_confirmed = ? WHERE id = ?", confirmed, id)
	if err != nil {
		return fmt.Errorf("update email confirmed: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("update email confirmed: %w", repos.ErrNoRecord)
	}
	return nil
}

func (u *userRepository) Delete(ctx context.Context, id string) error {
	result, err := u.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("delete user: %w", repos.ErrNoRecord)
	}
	return nil
}
