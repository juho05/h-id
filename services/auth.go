package services

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/alexedwards/scs/v2"

	"github.com/Bananenpro/h-id/config"
	"github.com/Bananenpro/h-id/repos"
)

type AuthService interface {
	Login(ctx context.Context, email, password string) error
	HashPassword(password string) ([]byte, error)
	VerifyPassword(user *repos.UserModel, password string) error
	VerifyPasswordByID(ctx context.Context, id, password string) error
}

type authService struct {
	userRepo       repos.UserRepository
	sessionManager *scs.SessionManager
}

func NewAuthService(userRepository repos.UserRepository, sessionManager *scs.SessionManager) AuthService {
	return &authService{
		userRepo:       userRepository,
		sessionManager: sessionManager,
	}
}

func (a *authService) Login(ctx context.Context, email, password string) error {
	user, err := a.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			return ErrInvalidCredentials
		} else {
			return fmt.Errorf("login: %w", err)
		}
	}

	if err = bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		return ErrInvalidCredentials
	}

	err = a.sessionManager.RenewToken(ctx)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	a.sessionManager.Put(ctx, "authUserID", user.ID)
	return nil
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
