package services

import (
	"context"
	"fmt"

	"github.com/Bananenpro/h-id/repos"
)

type UserService interface {
	Find(ctx context.Context, id string) (*repos.UserModel, error)
	Create(ctx context.Context, name, email, password string) (*repos.UserModel, error)
	Delete(ctx context.Context, id, password string) error

	FindClient(ctx context.Context, userID, clientID string) (*repos.ClientModel, error)
	FindClients(ctx context.Context, userID string) ([]*repos.ClientModel, error)
	CreateClient(ctx context.Context, userID, name, description string, redirectURIs []string) (*repos.ClientModel, string, error)
	UpdateClient(ctx context.Context, userID, clientID, name, description string, redirectURIs []string) error
	ClientRotateSecret(ctx context.Context, userID, clientID string) (string, error)
	DeleteClient(ctx context.Context, userID, clientID string) error
}

type userService struct {
	userRepo    repos.UserRepository
	clientRepo  repos.ClientRepository
	authService AuthService
}

func NewUserService(userRepository repos.UserRepository, clientRepository repos.ClientRepository, authService AuthService) UserService {
	return &userService{
		userRepo:    userRepository,
		clientRepo:  clientRepository,
		authService: authService,
	}
}

func (u *userService) FindClient(ctx context.Context, userID, clientID string) (*repos.ClientModel, error) {
	return u.clientRepo.Find(ctx, userID, clientID)
}

func (u *userService) FindClients(ctx context.Context, userID string) ([]*repos.ClientModel, error) {
	return u.clientRepo.FindByUserID(ctx, userID)
}

func (u *userService) CreateClient(ctx context.Context, userID, name, description string, redirectURIs []string) (*repos.ClientModel, string, error) {
	secret := generateToken(64)
	secretHash := hashToken(secret)
	client, err := u.clientRepo.Create(ctx, userID, name, description, redirectURIs, secretHash)
	if err != nil {
		return nil, "", fmt.Errorf("create client: %w", err)
	}
	return client, secret, nil
}

func (u *userService) UpdateClient(ctx context.Context, userID, clientID, name, description string, redirectURIs []string) error {
	return u.clientRepo.Update(ctx, userID, clientID, name, description, redirectURIs)
}

func (u *userService) ClientRotateSecret(ctx context.Context, userID, clientID string) (string, error) {
	secret := generateToken(64)
	secretHash := hashToken(secret)
	err := u.clientRepo.UpdateSecret(ctx, userID, clientID, secretHash)
	if err != nil {
		return "", fmt.Errorf("rotate client secret: %w", err)
	}
	return secret, nil
}

func (u *userService) DeleteClient(ctx context.Context, userID, clientID string) error {
	return u.clientRepo.Delete(ctx, userID, clientID)
}

func (u *userService) Find(ctx context.Context, id string) (*repos.UserModel, error) {
	return u.userRepo.Find(ctx, id)
}

func (u *userService) Create(ctx context.Context, name, email, password string) (*repos.UserModel, error) {
	tx, err := u.userRepo.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	passwordHash, err := u.authService.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user, err := tx.Create(name, email, passwordHash)
	if err != nil {
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (u *userService) Delete(ctx context.Context, id, password string) error {
	tx, err := u.userRepo.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err = u.authService.VerifyPasswordByID(ctx, id, password); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	err = tx.Delete(id)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}
