package services

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"

	"github.com/Bananenpro/h-id/config"
	"github.com/Bananenpro/h-id/repos"
)

type AuthService interface {
	HashPassword(password string) ([]byte, error)
	VerifyPassword(user *repos.UserModel, password string) error
	VerifyPasswordByID(ctx context.Context, id, password string) error
}

type authService struct {
	userRepo repos.UserRepository
}

func NewAuthService(userRepository repos.UserRepository) AuthService {
	return &authService{
		userRepo: userRepository,
	}
}

func (a *authService) HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), config.BcryptCost())
}

func (a *authService) VerifyPassword(user *repos.UserModel, password string) error {
	err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrInvalidCredentials
	}
	return err
}

func (a *authService) VerifyPasswordByID(ctx context.Context, id, password string) error {
	hash, err := a.userRepo.GetPasswordHash(ctx, id)
	if err != nil {
		return err
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrInvalidCredentials
	}
	return err
}
