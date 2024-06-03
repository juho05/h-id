package postgres

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/repos/postgres/db"
)

type clientRepository struct {
	db queryStore
}

func (d *DB) NewClientRepository() repos.ClientRepository {
	return &clientRepository{
		db: d.db,
	}
}

func repoClients(clients []db.Client) ([]*repos.ClientModel, error) {
	repoClients := make([]*repos.ClientModel, len(clients))
	for i, client := range clients {
		c, err := repoClient(client)
		if err != nil {
			return nil, err
		}
		repoClients[i] = c
	}
	return repoClients, nil
}

func repoClient(client db.Client) (*repos.ClientModel, error) {
	id, err := ulid.Parse(client.ID)
	if err != nil {
		return nil, err
	}
	userID, err := ulid.Parse(client.UserID)
	if err != nil {
		return nil, err
	}
	website, err := url.Parse(client.Website)
	if err != nil {
		return nil, err
	}
	redirectURLs, err := urlsFromJSON(client.RedirectUris)
	if err != nil {
		return nil, err
	}
	return &repos.ClientModel{
		BaseModel: repos.BaseModel{
			ID:        id,
			CreatedAt: time.Unix(client.CreatedAt, 0),
		},
		Name:         client.Name,
		Description:  client.Description,
		Website:      website,
		RedirectURIs: redirectURLs,
		SecretHash:   client.SecretHash,
		UserID:       userID,
	}, nil
}

func (c *clientRepository) Find(ctx context.Context, id ulid.ULID) (*repos.ClientModel, error) {
	client, err := c.db.FindClient(ctx, id.String())
	if err != nil {
		return nil, repoErr("find client: %w", err)
	}
	return repoClient(client)
}

func (c *clientRepository) FindByUserAndID(ctx context.Context, userID, id ulid.ULID) (*repos.ClientModel, error) {
	client, err := c.db.FindClientByUserAndID(ctx, db.FindClientByUserAndIDParams{
		ID:     id.String(),
		UserID: userID.String(),
	})
	if err != nil {
		return nil, repoErr("find client by user and ID: %w", err)
	}
	return repoClient(client)
}

func (c *clientRepository) FindByUser(ctx context.Context, userID ulid.ULID) ([]*repos.ClientModel, error) {
	clients, err := c.db.FindClientByUser(ctx, userID.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return make([]*repos.ClientModel, 0), nil
		}
		return nil, repoErr("find client by user: %w", err)
	}
	return repoClients(clients)
}

func (c *clientRepository) Create(ctx context.Context, userID ulid.ULID, name, description string, website *url.URL, redirectURIs []*url.URL, secretHash []byte) (*repos.ClientModel, error) {
	redirectURIsJSON, err := urlsToJSON(redirectURIs)
	if err != nil {
		return nil, err
	}
	client, err := c.db.CreateClient(ctx, db.CreateClientParams{
		ID:           ulid.Make().String(),
		CreatedAt:    time.Now().Unix(),
		Name:         name,
		Description:  description,
		Website:      website.String(),
		RedirectUris: redirectURIsJSON,
		SecretHash:   secretHash,
		UserID:       userID.String(),
	})
	if err != nil {
		return nil, repoErr("create client: %w", err)
	}
	return repoClient(client)
}

func (c *clientRepository) Update(ctx context.Context, userID, id ulid.ULID, name, description string, website *url.URL, redirectURIs []*url.URL) (*repos.ClientModel, error) {
	redirectURIsJSON, err := urlsToJSON(redirectURIs)
	if err != nil {
		return nil, err
	}
	client, err := c.db.UpdateClient(ctx, db.UpdateClientParams{
		UserID:       userID.String(),
		ID:           id.String(),
		Name:         name,
		Description:  description,
		Website:      website.String(),
		RedirectUris: redirectURIsJSON,
	})
	if err != nil {
		return nil, repoErr("update client: %w", err)
	}
	return repoClient(client)
}

func (c *clientRepository) UpdateSecret(ctx context.Context, userID, id ulid.ULID, newSecretHash []byte) error {
	result, err := c.db.UpdateClientSecret(ctx, db.UpdateClientSecretParams{
		UserID:     userID.String(),
		ID:         id.String(),
		SecretHash: newSecretHash,
	})
	return repoErrResult("update client secret: %w", result, err)
}

func (c *clientRepository) Delete(ctx context.Context, userID, id ulid.ULID) error {
	result, err := c.db.DeleteClient(ctx, db.DeleteClientParams{
		UserID: userID.String(),
		ID:     id.String(),
	})
	return repoErrResult("delete client: %w", result, err)
}
