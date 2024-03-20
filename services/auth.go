package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slices"

	"github.com/alexedwards/scs/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/oklog/ulid/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/xdg-go/pbkdf2"

	"github.com/juho05/log"

	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/repos"
)

type AuthService interface {
	PublicJWTKey() *rsa.PublicKey

	Login(ctx context.Context, userID ulid.ULID) error
	VerifyUsernamePassword(ctx context.Context, email, password string) (*repos.UserModel, error)
	Logout(ctx context.Context) error
	HashPassword(password string) ([]byte, error)
	VerifyPassword(user *repos.UserModel, password string) error
	VerifyPasswordByID(ctx context.Context, id ulid.ULID, password string) error
	AuthenticatedUserID(ctx context.Context) ulid.ULID
	AuthorizedScopes(ctx context.Context) []string
	IsEmailConfirmed(ctx context.Context, id ulid.ULID) (bool, error)
	SendConfirmEmail(r *http.Request, ctx context.Context, user *repos.UserModel) error
	ConfirmEmail(ctx context.Context, userID ulid.ULID, code string) error

	GenerateOTPKey(ctx context.Context, user *repos.UserModel) (*otp.Key, error)
	ActivateOTPKey(ctx context.Context, userID ulid.ULID, code string) error
	VerifyOTPCode(ctx context.Context, userID ulid.ULID, code string) error
	IsOTPActive(ctx context.Context, id ulid.ULID) (bool, error)

	StartOAuthCodeFlow(ctx context.Context, clientID ulid.ULID, redirectURI *url.URL, responseType, scope, state, nonce string) error
	GetAuthRequest(ctx context.Context) (AuthRequest, error)
	OAuthConsent(ctx context.Context) (string, error)
	OAuthGenerateTokens(ctx context.Context, clientID ulid.ULID, clientSecret string, redirectURI *url.URL, grantType, grant string) (access string, refresh string, id string, err error)
	VerifyClientCredentials(ctx context.Context, clientID ulid.ULID, clientSecret string) error
	RevokeOAuthTokens(ctx context.Context, clientID, userID ulid.ULID) error

	VerifyAccessToken(ctx context.Context, token string, requiredScopes []string) (userID ulid.ULID, scopes []string, err error)

	DescribeScopes(lang string, scopes []string) []string
}

type (
	AuthUserIDCtxKey struct{}
	AuthScopesCtxKey struct{}
)

func init() {
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		log.Fatalf("crypto/rand is unavailable: Read() failed with %#v", err)
	}

	gob.Register(ulid.ULID{})
	gob.Register(AuthRequest{})
}

type authService struct {
	userRepo       repos.UserRepository
	clientRepo     repos.ClientRepository
	tokenRepo      repos.TokenRepository
	oauthRepo      repos.OAuthRepository
	systemRepo     repos.SystemRepository
	sessionManager *scs.SessionManager
	emailService   EmailService

	jwtKeyPriv *rsa.PrivateKey
	jwtKeyPub  *rsa.PublicKey
}

type AuthRequest struct {
	ClientID     ulid.ULID
	RedirectURI  *url.URL
	Scopes       []string
	State        string
	Nonce        string
	NeedsConsent bool
}

func NewAuthService(userRepository repos.UserRepository, tokenRepository repos.TokenRepository, oauthRepository repos.OAuthRepository, clientRepository repos.ClientRepository, systemRepository repos.SystemRepository, sessionManager *scs.SessionManager, emailService EmailService) (AuthService, error) {
	a := &authService{
		userRepo:       userRepository,
		tokenRepo:      tokenRepository,
		oauthRepo:      oauthRepository,
		clientRepo:     clientRepository,
		systemRepo:     systemRepository,
		sessionManager: sessionManager,
		emailService:   emailService,
	}
	err := a.initKeys(context.Background())
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (a *authService) initKeys(ctx context.Context) error {
	if priv, pub, err := a.systemRepo.GetJWTKeys(ctx); err == nil {
		a.jwtKeyPriv = priv
		a.jwtKeyPub = pub
		log.Info("Using existing JWT keys...")
	} else if errors.Is(err, repos.ErrNoRecord) {
		log.Info("Generating new JWT keys...")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generate JWT RSA keys: %w", err)
		}
		err = a.systemRepo.InsertJWTKeys(ctx, key, &key.PublicKey)
		if err != nil {
			return fmt.Errorf("init keys: %w", err)
		}
		a.jwtKeyPriv = key
		a.jwtKeyPub = &key.PublicKey
	} else {
		return fmt.Errorf("init keys: %w", err)
	}
	return nil
}

func (a *authService) PublicJWTKey() *rsa.PublicKey {
	return a.jwtKeyPub
}

func (a *authService) StartOAuthCodeFlow(ctx context.Context, clientID ulid.ULID, redirectURI *url.URL, responseType, scope, state, nonce string) error {
	client, err := a.clientRepo.Find(ctx, clientID)
	if err != nil {
		return fmt.Errorf("start OAuth code flow: %w", err)
	}

	var validRedirectURI bool
	redirectURIStr := redirectURI.String()
	for _, ru := range client.RedirectURIs {
		if ru.String() == redirectURIStr {
			validRedirectURI = true
			break
		}
	}
	if !validRedirectURI {
		return ErrInvalidRedirectURI
	}

	if responseType != "code" {
		return ErrUnsupportedResponseType
	}

	scopes := strings.Split(scope, " ")
	for _, s := range scopes {
		if s != "openid" && s != "profile" && s != "email" {
			return fmt.Errorf("%w: %s", ErrInvalidScope, s)
		}
	}

	needsConsent := false
	permissions, err := a.oauthRepo.FindPermissions(ctx, clientID, a.AuthenticatedUserID(ctx))
	if err == nil {
		for _, s := range scopes {
			if !slices.Contains(permissions.Scopes, s) {
				needsConsent = true
				break
			}
		}
	} else {
		needsConsent = true
	}

	a.sessionManager.Put(ctx, "authRequest", AuthRequest{
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
		State:        state,
		Nonce:        nonce,
		NeedsConsent: needsConsent,
	})

	return nil
}

func (a *authService) GetAuthRequest(ctx context.Context) (AuthRequest, error) {
	req, ok := a.sessionManager.Get(ctx, "authRequest").(AuthRequest)
	if !ok {
		return AuthRequest{}, ErrMissingRequiredSessionData
	}
	return req, nil
}

func (a *authService) OAuthConsent(ctx context.Context) (string, error) {
	req, err := a.GetAuthRequest(ctx)
	if err != nil {
		return "", fmt.Errorf("OAuth consent: %w", err)
	}
	code := generateToken(64)
	codeHash := hashTokenWeak(code)

	userID := a.AuthenticatedUserID(ctx)
	_, err = a.oauthRepo.SetPermissions(ctx, req.ClientID, userID, req.Scopes)
	if err != nil {
		return "", fmt.Errorf("OAuth consent: %w", err)
	}

	_, err = a.oauthRepo.Create(ctx, req.ClientID, userID, repos.OAuthTokenCode, codeHash, req.RedirectURI, req.Scopes, []byte(req.Nonce), 1*time.Minute)
	if err != nil {
		return "", fmt.Errorf("OAuth consent: %w", err)
	}
	return code, nil
}

func (a *authService) OAuthGenerateTokens(ctx context.Context, clientID ulid.ULID, clientSecret string, redirectURI *url.URL, grantType, grant string) (string, string, string, error) {
	if err := a.VerifyClientCredentials(ctx, clientID, clientSecret); err != nil {
		return "", "", "", fmt.Errorf("oauth generate tokens: %w", err)
	}

	var hash []byte
	var tokenType repos.OAuthTokenCategory
	switch grantType {
	case "authorization_code":
		hash = hashTokenWeak(grant)
		tokenType = repos.OAuthTokenCode
	case "refresh_token":
		hash = hashTokenWeak(grant)
		tokenType = repos.OAuthTokenRefresh
	default:
		return "", "", "", ErrUnsupportedGrantType
	}

	token, err := a.oauthRepo.Find(ctx, tokenType, hash)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			err = ErrInvalidGrant
		}
		return "", "", "", fmt.Errorf("oauth generate tokens: %w", err)
	}
	if token.ClientID != clientID {
		return "", "", "", fmt.Errorf("oauth generate tokens: %w", ErrInvalidGrant)
	}
	if token.Used {
		err = a.RevokeOAuthTokens(ctx, clientID, token.UserID)
		if err != nil {
			log.Errorf("%s\n%s", fmt.Sprintf("oauth generate tokens: %s", err), debug.Stack())
		}
		return "", "", "", ErrReusedToken
	}

	if grantType != "refresh_token" && token.RedirectURI.String() != redirectURI.String() {
		return "", "", "", fmt.Errorf("oauth generate tokens: %w", ErrInvalidRedirectURI)
	}

	err = a.oauthRepo.Use(ctx, clientID, tokenType, token.TokenHash)
	if err != nil {
		return "", "", "", fmt.Errorf("oauth generate tokens: %w", err)
	}

	access := generateToken(64)
	accessHash := hashTokenWeak(access)
	refresh := generateToken(128)
	refreshHash := hashTokenWeak(refresh)

	_, err = a.oauthRepo.Create(ctx, token.ClientID, token.UserID, repos.OAuthTokenAccess, accessHash, nil, token.Scopes, nil, 30*time.Minute)
	if err != nil {
		return "", "", "", fmt.Errorf("oauth tokens by code: %w", err)
	}

	_, err = a.oauthRepo.Create(ctx, token.ClientID, token.UserID, repos.OAuthTokenRefresh, refreshHash, nil, token.Scopes, nil, 12*7*24*time.Hour)
	if err != nil {
		return "", "", "", fmt.Errorf("oauth tokens by code: %w", err)
	}

	var nonce string
	if grantType == "authorization_code" {
		nonce = string(token.Data)
	}

	var id string
	if slices.Contains(token.Scopes, "openid") {
		id, err = a.createIDToken(token.ClientID, token.UserID, nonce)
		if err != nil {
			return "", "", "", fmt.Errorf("oauth tokens by code: %w", err)
		}
	}

	return access, refresh, id, nil
}

func (a *authService) createIDToken(clientID, userID ulid.ULID, nonce string) (string, error) {
	type claims struct {
		jwt.RegisteredClaims
		Nonce string `json:"nonce,omitempty"`
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    config.BaseURL(),
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{clientID.String()},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: nonce,
	})
	return token.SignedString(a.jwtKeyPriv)
}

func (a *authService) VerifyClientCredentials(ctx context.Context, clientID ulid.ULID, clientSecret string) error {
	client, err := a.clientRepo.Find(ctx, clientID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			err = ErrInvalidCredentials
		}
		return fmt.Errorf("verify client credentials: %w", err)
	}
	if string(hashToken(clientSecret)) != string(client.SecretHash) {
		return ErrInvalidCredentials
	}
	return nil
}

func (a *authService) RevokeOAuthTokens(ctx context.Context, clientID, userID ulid.ULID) error {
	err := a.oauthRepo.DeleteByUser(ctx, clientID, userID)
	if err != nil {
		return fmt.Errorf("revoke OAuth tokens: %w", err)
	}
	return nil
}

func (a *authService) SendConfirmEmail(r *http.Request, ctx context.Context, user *repos.UserModel) error {
	if token, err := a.tokenRepo.Find(ctx, repos.TokenConfirmEmail, user.ID.String()); err == nil && time.Since(token.CreatedAt) < 2*time.Minute {
		return ErrTimeout
	} else if err != nil && !errors.Is(err, repos.ErrNoRecord) {
		return fmt.Errorf("check confirm email timeout: %w", err)
	}

	lang := GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	data := newEmailTemplateData(user.Name, lang)
	data.Code = generateCode(6)

	_, err := a.tokenRepo.Create(ctx, repos.TokenConfirmEmail, user.ID.String(), hashToken(data.Code), 2*time.Minute)
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

func (a *authService) ConfirmEmail(ctx context.Context, userID ulid.ULID, code string) error {
	token, err := a.tokenRepo.Find(ctx, repos.TokenConfirmEmail, userID.String())
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("confirm email: %w", err)
	}

	if subtle.ConstantTimeCompare(token.ValueHash, hashToken(code)) == 0 {
		return ErrInvalidCredentials
	}

	err = a.tokenRepo.Delete(ctx, repos.TokenConfirmEmail, userID.String())
	if err != nil {
		return fmt.Errorf("confirm email: %w", err)
	}

	err = a.userRepo.UpdateEmailConfirmed(ctx, userID, true)
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

func (a *authService) AuthenticatedUserID(ctx context.Context) ulid.ULID {
	value, ok := ctx.Value(AuthUserIDCtxKey{}).(ulid.ULID)
	if !ok {
		value, ok = a.sessionManager.Get(ctx, "authUserID").(ulid.ULID)
		if !ok {
			return ulid.ULID{}
		}
	}
	return value
}

func (a *authService) AuthorizedScopes(ctx context.Context) []string {
	value, _ := ctx.Value(AuthScopesCtxKey{}).([]string)
	return value
}

func (a *authService) IsEmailConfirmed(ctx context.Context, id ulid.ULID) (bool, error) {
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

func (a *authService) IsOTPActive(ctx context.Context, id ulid.ULID) (bool, error) {
	authUser := a.AuthenticatedUserID(ctx)
	if id == authUser && a.sessionManager.Exists(ctx, "otpActive") {
		return a.sessionManager.GetBool(ctx, "otpActive"), nil
	}
	user, err := a.userRepo.Find(ctx, id)
	if err != nil {
		return false, fmt.Errorf("is otp active: %w", err)
	}
	if id == authUser {
		a.sessionManager.Put(ctx, "otpActive", user.OTPActive)
	}
	return user.OTPActive, nil
}

func (a *authService) GenerateOTPKey(ctx context.Context, user *repos.UserModel) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "H-ID",
		AccountName: user.Email,
	})
	if err != nil {
		return nil, fmt.Errorf("generate OTP key: %w", err)
	}
	err = a.userRepo.UpdateOTP(ctx, user.ID, false, key)
	if err != nil {
		return nil, fmt.Errorf("update user OTP key: %w", err)
	}
	err = a.sessionManager.RenewToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("generate OTP key: %w", err)
	}
	a.sessionManager.Remove(ctx, "otpActive")
	return key, nil
}

func (a *authService) ActivateOTPKey(ctx context.Context, userID ulid.ULID, code string) error {
	err := a.VerifyOTPCode(ctx, userID, code)
	if err != nil {
		return fmt.Errorf("activate OTP: %w", err)
	}
	err = a.userRepo.UpdateOTP(ctx, userID, true, nil)
	if err != nil {
		return fmt.Errorf("activate OTP: %w", err)
	}
	err = a.sessionManager.RenewToken(ctx)
	if err != nil {
		return fmt.Errorf("activate OTP: %w", err)
	}
	a.sessionManager.Remove(ctx, "otpActive")
	return nil
}

func (a *authService) VerifyOTPCode(ctx context.Context, userID ulid.ULID, code string) error {
	_, key, err := a.userRepo.GetOTP(ctx, userID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("verify otp code: get otp: %w", err)
	}
	if key == nil {
		return fmt.Errorf("verify otp code: %w", ErrInvalidCredentials)
	}
	if !totp.Validate(code, key.Secret()) {
		return ErrInvalidCredentials
	}
	return nil
}

func (a *authService) VerifyUsernamePassword(ctx context.Context, email, password string) (*repos.UserModel, error) {
	user, err := a.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			return nil, ErrInvalidCredentials
		} else {
			return nil, fmt.Errorf("verify username/password: %w", err)
		}
	}
	if err = bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}
	err = a.sessionManager.RenewToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify username/password: %w", err)
	}
	a.sessionManager.Put(ctx, "validPassword", user.ID)
	return user, nil
}

func (a *authService) Login(ctx context.Context, userID ulid.ULID) error {
	err := a.sessionManager.RenewToken(ctx)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	a.sessionManager.Put(ctx, "authUserID", userID)
	a.sessionManager.Remove(ctx, "validPassword")
	return nil
}

func (a *authService) Logout(ctx context.Context) error {
	err := a.sessionManager.Destroy(ctx)
	if err != nil {
		return fmt.Errorf("logout: %w", err)
	}
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

func (a *authService) VerifyPasswordByID(ctx context.Context, id ulid.ULID, password string) error {
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

func (a *authService) VerifyAccessToken(ctx context.Context, token string, requiredScopes []string) (ulid.ULID, []string, error) {
	access, err := a.oauthRepo.Find(ctx, repos.OAuthTokenAccess, hashTokenWeak(token))
	if err != nil {
		return ulid.ULID{}, nil, fmt.Errorf("verify access token: %w", ErrInvalidCredentials)
	}
	for _, s := range requiredScopes {
		if !slices.Contains(access.Scopes, s) {
			return ulid.ULID{}, nil, ErrInsufficientScope
		}
	}
	return access.UserID, access.Scopes, nil
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
	return pbkdf2.Key([]byte(token), []byte("salt"), 10000, 256, sha256.New)
}

func hashTokenWeak(token string) []byte {
	return pbkdf2.Key([]byte(token), []byte("salt"), 5000, 256, sha256.New)
}

func (a *authService) DescribeScopes(lang string, scopes []string) []string {
	descriptions := make([]string, 0, len(scopes))
	for _, s := range scopes {
		// [...] requests permission to:
		switch s {
		case "openid":
		case "profile":
			d, _ := Translate(lang, "scopesProfile")
			descriptions = append(descriptions, d)
		case "email":
			d, _ := Translate(lang, "scopesEmail")
			descriptions = append(descriptions, d)
		default:
			descriptions = append(descriptions, s)
		}
	}
	return descriptions
}
