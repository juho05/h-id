package repos

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"
)

type GatewayTokenModel struct {
	CreatedAt time.Time
	UserID    ulid.ULID
	TokenHash []byte
	Expires   time.Time
}

type GatewayTokenRepository interface {
	Create(ctx context.Context, userID ulid.ULID, tokenHash []byte, lifetime time.Duration) error
	FindByHash(ctx context.Context, tokenHash []byte) (*GatewayTokenModel, error)
	Delete(ctx context.Context, tokenHash []byte) error
	DeleteByUser(ctx context.Context, userID ulid.ULID) error
}
