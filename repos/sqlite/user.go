package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/mattn/go-sqlite3"

	"github.com/Bananenpro/h-id/repos"
)

type userRepository struct {
	db *sqlx.DB
}

type userTransaction struct {
	tx *sqlx.Tx
}

func (db *DB) NewUserRepository() repos.UserRepository {
	return &userRepository{
		db: db.db,
	}
}

func (u *userRepository) BeginTransaction(ctx context.Context) (repos.UserTransaction, error) {
	tx, err := u.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin user transaction: %w", err)
	}
	return &userTransaction{
		tx: tx,
	}, nil
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

func (u *userTransaction) Create(name, email string, passwordHash []byte) (*repos.UserModel, error) {
	user := &repos.UserModel{
		BaseModel:      newBase(),
		Name:           name,
		Email:          email,
		EmailConfirmed: false,
		PasswordHash:   passwordHash,
	}
	_, err := u.tx.Exec("INSERT INTO users (id, created_at, name, email, email_confirmed, password_hash) VALUES (?, ?, ?, ?, ?, ?)", user.ID, user.CreatedAt, user.Name, user.Email, user.EmailConfirmed, user.PasswordHash)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrConstraint && strings.Contains(sqliteErr.Error(), "email") {
			err = repos.ErrDuplicateEmail
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (u *userTransaction) UpdateEmailConfirmed(id string, confirmed bool) error {
	result, err := u.tx.Exec("UPDATE users SET email_confirmed = ? WHERE id = ?", confirmed, id)
	if err != nil {
		return fmt.Errorf("update email confirmed: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("update email confirmed: %w", repos.ErrNoRecord)
	}
	return nil
}

func (u *userTransaction) Delete(id string) error {
	result, err := u.tx.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("delete user: %w", repos.ErrNoRecord)
	}
	return nil
}

func (u *userTransaction) Commit() error {
	err := u.tx.Commit()
	if err != nil {
		return fmt.Errorf("commit user transaction: %w", err)
	}
	return nil
}

func (u *userTransaction) Rollback() error {
	err := u.tx.Rollback()
	if err != nil {
		return fmt.Errorf("rollback user transaction: %w", err)
	}
	return nil
}
