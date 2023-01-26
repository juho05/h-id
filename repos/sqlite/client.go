package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/Bananenpro/h-id/repos"
)

type clientRepository struct {
	db *sqlx.DB
}

func (d *DB) NewClientRepository() repos.ClientRepository {
	return &clientRepository{
		db: d.db,
	}
}

func (c *clientRepository) Find(ctx context.Context, id string) (*repos.ClientModel, error) {
	var client repos.ClientModel
	err := c.db.GetContext(ctx, &client, "SELECT * FROM clients WHERE id = ?", id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = repos.ErrNoRecord
		}
		return nil, fmt.Errorf("find client: %w", err)
	}
	return &client, nil
}

func (c *clientRepository) FindByUserAndID(ctx context.Context, userID, id string) (*repos.ClientModel, error) {
	var client repos.ClientModel
	err := c.db.GetContext(ctx, &client, "SELECT * FROM clients WHERE user_id = ? AND id = ?", userID, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = repos.ErrNoRecord
		}
		return nil, fmt.Errorf("find client by user and id: %w", err)
	}
	return &client, nil
}

func (c *clientRepository) FindByUser(ctx context.Context, userID string) ([]*repos.ClientModel, error) {
	var clients []*repos.ClientModel
	err := c.db.SelectContext(ctx, &clients, "SELECT * FROM clients WHERE user_id = ?", userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return make([]*repos.ClientModel, 0), nil
		}
		return nil, fmt.Errorf("find client: %w", err)
	}
	return clients, nil
}

func (c *clientRepository) Create(ctx context.Context, userID, name, description, website string, redirectURIs []string, secretHash []byte) (*repos.ClientModel, error) {
	client := &repos.ClientModel{
		BaseModel:    newBase(),
		Name:         name,
		Description:  description,
		Website:      website,
		RedirectURIs: redirectURIs,
		SecretHash:   secretHash,
		UserID:       userID,
	}
	_, err := c.db.ExecContext(ctx, "INSERT INTO clients (id, created_at, name, description, website, redirect_uris, secret_hash, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", client.ID, client.CreatedAt, client.Name, client.Description, client.Website, client.RedirectURIs, client.SecretHash, client.UserID)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	return client, nil
}

func (c *clientRepository) Update(ctx context.Context, userID, id, name, description, website string, redirectURIs []string) error {
	result, err := c.db.ExecContext(ctx, "UPDATE clients SET name = ?, description = ?, website = ?, redirect_uris = ? WHERE user_id = ? AND id = ?", name, description, website, redirectURIs, userID, id)
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("update client: %w", repos.ErrNoRecord)
	}
	return nil
}

func (c *clientRepository) UpdateSecret(ctx context.Context, userID, id string, newSecretHash []byte) error {
	result, err := c.db.ExecContext(ctx, "UPDATE clients SET secret_hash = ? WHERE user_id = ? AND id = ?", newSecretHash, userID, id)
	if err != nil {
		return fmt.Errorf("update client secret: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("update client secret: %w", repos.ErrNoRecord)
	}
	return nil
}

func (c *clientRepository) Delete(ctx context.Context, userID, id string) error {
	result, err := c.db.ExecContext(ctx, "DELETE FROM clients WHERE user_id = ? AND id = ?", userID, id)
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("delete client: %w", repos.ErrNoRecord)
	}
	return nil
}
