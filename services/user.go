package services

import (
	"context"
	"fmt"

	"github.com/Bananenpro/h-id/repos"
)

type UserService interface {
	Create(ctx context.Context, name, email, password string) (*repos.UserModel, error)
	Delete(ctx context.Context, id, password string) error
}

type userService struct {
	userRepo    repos.UserRepository
	authService AuthService
}

func NewUserService(userRepository repos.UserRepository, authService AuthService) UserService {
	return &userService{
		userRepo:    userRepository,
		authService: authService,
	}
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
