package repos

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type DB interface {
	NewUserRepository() UserRepository
	NewSessionRepository() SessionRepository
	NewTokenRepository() TokenRepository
	NewClientRepository() ClientRepository
	NewOAuthRepository() OAuthRepository
}

type Transaction interface {
	Commit() error
	Rollback() error
}

type BaseModel struct {
	ID        string `db:"id"`
	CreatedAt int64  `db:"created_at"`
}

type StringSlice []string

func (s *StringSlice) Scan(source any) error {
	if source == nil {
		*s = nil
		return nil
	}
	src, ok := source.(string)
	if !ok {
		panic("cannot scan non-string into StringSlice")
	}
	return json.Unmarshal([]byte(src), s)
}

func (s StringSlice) Value() (driver.Value, error) {
	value, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal StringSlice: %w", err)
	}
	return string(value), nil
}
