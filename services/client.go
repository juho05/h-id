package services

import (
	"context"
	"fmt"

	"github.com/juho05/h-id/repos"
)

type ClientService interface {
	Find(ctx context.Context, id string) (*repos.ClientModel, error)
	FindByUserAndID(ctx context.Context, userID, clientID string) (*repos.ClientModel, error)
	FindByUser(ctx context.Context, userID string) ([]*repos.ClientModel, error)
	Create(ctx context.Context, userID, name, description, website string, redirectURIs []string) (*repos.ClientModel, string, error)
	Update(ctx context.Context, userID, clientID, name, description, website string, redirectURIs []string) error
	ClientRotateSecret(ctx context.Context, userID, clientID string) (string, error)
	Delete(ctx context.Context, userID, clientID string) error
}

type clientService struct {
	clientRepo repos.ClientRepository
}

func NewClientService(clientRepository repos.ClientRepository) ClientService {
	return &clientService{
		clientRepo: clientRepository,
	}
}

func (c *clientService) Find(ctx context.Context, clientID string) (*repos.ClientModel, error) {
	return c.clientRepo.Find(ctx, clientID)
}

func (c *clientService) FindByUserAndID(ctx context.Context, userID, clientID string) (*repos.ClientModel, error) {
	return c.clientRepo.FindByUserAndID(ctx, userID, clientID)
}

func (c *clientService) FindByUser(ctx context.Context, userID string) ([]*repos.ClientModel, error) {
	return c.clientRepo.FindByUser(ctx, userID)
}

func (c *clientService) Create(ctx context.Context, userID, name, description, website string, redirectURIs []string) (*repos.ClientModel, string, error) {
	secret := generateToken(64)
	secretHash := hashToken(secret)
	client, err := c.clientRepo.Create(ctx, userID, name, description, website, redirectURIs, secretHash)
	if err != nil {
		return nil, "", fmt.Errorf("create client: %w", err)
	}
	return client, secret, nil
}

func (c *clientService) Update(ctx context.Context, userID, clientID, name, description, website string, redirectURIs []string) error {
	return c.clientRepo.Update(ctx, userID, clientID, name, description, website, redirectURIs)
}

func (c *clientService) ClientRotateSecret(ctx context.Context, userID, clientID string) (string, error) {
	secret := generateToken(64)
	secretHash := hashToken(secret)
	err := c.clientRepo.UpdateSecret(ctx, userID, clientID, secretHash)
	if err != nil {
		return "", fmt.Errorf("rotate client secret: %w", err)
	}
	return secret, nil
}

func (c *clientService) Delete(ctx context.Context, userID, clientID string) error {
	return c.clientRepo.Delete(ctx, userID, clientID)
}
