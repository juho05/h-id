package repos

import (
	"context"
	"time"
)

type TokenCategory string

var TokenConfirmEmail TokenCategory = "confirm-email"

type TokenModel struct {
	CreatedAt time.Time
	Category  TokenCategory
	Key       string
	ValueHash []byte
	Expires   time.Time
}

type TokenRepository interface {
	Create(ctx context.Context, category TokenCategory, key string, valueHash []byte, lifetime time.Duration) (*TokenModel, error)
	Find(ctx context.Context, category TokenCategory, key string) (*TokenModel, error)
	Delete(ctx context.Context, category TokenCategory, key string) error
}
