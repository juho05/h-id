package repos

import (
	"time"

	"github.com/oklog/ulid/v2"
)

type DB interface {
	NewSystemRepository() SystemRepository
	NewUserRepository() UserRepository
	NewSessionRepository() SessionRepository
	NewTokenRepository() TokenRepository
	NewClientRepository() ClientRepository
	NewOAuthRepository() OAuthRepository

	Close() error
}

type BaseModel struct {
	ID        ulid.ULID
	CreatedAt time.Time
}
