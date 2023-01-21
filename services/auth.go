package services

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/alexedwards/scs/v2"
	"github.com/xdg-go/pbkdf2"

	"github.com/Bananenpro/log"

	"github.com/Bananenpro/h-id/config"
	"github.com/Bananenpro/h-id/repos"
)

type AuthService interface {
	Login(ctx context.Context, email, password string) error
	HashPassword(password string) ([]byte, error)
	VerifyPassword(user *repos.UserModel, password string) error
	VerifyPasswordByID(ctx context.Context, id, password string) error
	AuthenticatedUserID(ctx context.Context) string
	IsEmailConfirmed(ctx context.Context, id string) (bool, error)
	SendConfirmEmail(ctx context.Context, user *repos.UserModel) error
	ConfirmEmail(ctx context.Context, userID, code string) error
}

func init() {
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		log.Fatalf("crypto/rand is unavailable: Read() failed with %#v", err)
	}
}

type authService struct {
	userRepo       repos.UserRepository
	tokenRepo      repos.TokenRepository
	sessionManager *scs.SessionManager
	emailService   EmailService
}

func NewAuthService(userRepository repos.UserRepository, tokenRepository repos.TokenRepository, sessionManager *scs.SessionManager, emailService EmailService) AuthService {
	return &authService{
		userRepo:       userRepository,
		tokenRepo:      tokenRepository,
		sessionManager: sessionManager,
		emailService:   emailService,
	}
}

func (a *authService) SendConfirmEmail(ctx context.Context, user *repos.UserModel) error {
	if token, err := a.tokenRepo.Find(ctx, repos.TokenConfirmEmail, user.ID); err == nil && time.Since(time.Unix(token.CreatedAt, 0)) < 2*time.Minute {
		return ErrTimeout
	} else if err != nil && !errors.Is(err, repos.ErrNoRecord) {
		return fmt.Errorf("check confirm email timeout: %w", err)
	}

	data := newEmailTemplateData(user.Name)
	data.Code = generateCode(6)

	_, err := a.tokenRepo.Create(ctx, repos.TokenConfirmEmail, user.ID, hashToken(data.Code), 2*time.Minute)
	if err != nil {
		return fmt.Errorf("create email confirmation token: %w", err)
	}

	go func() {
		err := a.emailService.SendEmail(user.Email, "Confirm Email", "confirmEmail", data)
		if err != nil {
			log.Errorf("Failed to send email: %s", err)
		}
	}()
	return nil
}

func (a *authService) ConfirmEmail(ctx context.Context, userID, code string) error {
	token, err := a.tokenRepo.Find(ctx, repos.TokenConfirmEmail, userID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("confirm email: %w", err)
	}

	if subtle.ConstantTimeCompare(token.ValueHash, hashToken(code)) == 0 {
		return ErrInvalidCredentials
	}

	err = a.tokenRepo.Delete(ctx, repos.TokenConfirmEmail, userID)
	if err != nil {
		return fmt.Errorf("confirm email: %w", err)
	}

	tx, err := a.userRepo.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("confirm email: %w", err)
	}
	defer tx.Rollback()

	err = tx.UpdateEmailConfirmed(userID, true)
	if err != nil {
		return fmt.Errorf("confirm email: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("confirm email: %w", err)
	}

	err = a.sessionManager.RenewToken(ctx)
	if err != nil {
		return fmt.Errorf("confirm email: %w", err)
	}

	a.sessionManager.Remove(ctx, "emailConfirmed")
	return nil
}

func (a *authService) AuthenticatedUserID(ctx context.Context) string {
	return a.sessionManager.GetString(ctx, "authUserID")
}

func (a *authService) IsEmailConfirmed(ctx context.Context, id string) (bool, error) {
	authUser := a.AuthenticatedUserID(ctx)
	if id == authUser && a.sessionManager.Exists(ctx, "emailConfirmed") {
		return a.sessionManager.GetBool(ctx, "emailConfirmed"), nil
	}
	user, err := a.userRepo.Find(ctx, id)
	if err != nil {
		return false, fmt.Errorf("is email confirmed: %w", err)
	}
	if id == authUser {
		a.sessionManager.Put(ctx, "emailConfirmed", user.EmailConfirmed)
	}
	return user.EmailConfirmed, nil
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

func generateCode(length int) string {
	if length > 18 {
		panic("cannot generate code with >18 digits")
	}
	length -= 1
	code, err := rand.Int(rand.Reader, big.NewInt(int64(math.Pow10(length+1)-math.Pow10(length))))
	if err != nil {
		panic(err)
	}
	c := code.Int64()
	c += int64(math.Pow10(length))
	return fmt.Sprintf("%v", c)
}

func generateToken(length int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}

func hashToken(token string) []byte {
	return pbkdf2.Key([]byte(token), []byte("salt"), 100000, 64, sha512.New)
}
