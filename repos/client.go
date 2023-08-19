package repos

import (
	"context"
	"net/url"

	"github.com/oklog/ulid/v2"
)

type ClientModel struct {
	BaseModel
	Name         string
	Description  string
	Website      *url.URL
	RedirectURIs []*url.URL
	SecretHash   []byte
	UserID       ulid.ULID
}

type ClientRepository interface {
	Find(ctx context.Context, id ulid.ULID) (*ClientModel, error)
	FindByUserAndID(ctx context.Context, userID, id ulid.ULID) (*ClientModel, error)
	FindByUser(ctx context.Context, userID ulid.ULID) ([]*ClientModel, error)
	Create(ctx context.Context, userID ulid.ULID, name, description string, website *url.URL, redirectURIs []*url.URL, secretHash []byte) (*ClientModel, error)
	Update(ctx context.Context, userID, id ulid.ULID, name, description string, website *url.URL, redirectURIs []*url.URL) (*ClientModel, error)
	UpdateSecret(ctx context.Context, userID, id ulid.ULID, newSecretHash []byte) error
	Delete(ctx context.Context, userID, id ulid.ULID) error
}
