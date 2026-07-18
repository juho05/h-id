package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	hid "github.com/juho05/h-id"
	"github.com/juho05/h-id/repos/sqlite"
)

func newTestAuthService(t *testing.T) *authService {
	t.Helper()
	os.Setenv("AUTO_MIGRATE", "true")
	os.Setenv("BASE_URL", "https://id.example.com")
	hid.Initialize()
	db, err := sqlite.Connect(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("connect sqlite: %s", err)
	}
	t.Cleanup(func() { db.Close() })
	return &authService{
		userRepo:         db.NewUserRepository(),
		gatewayTokenRepo: db.NewGatewayTokenRepository(),
	}
}

// createTestUser inserts a user so gateway tokens satisfy the foreign key.
func createTestUser(t *testing.T, a *authService) ulid.ULID {
	t.Helper()
	user, err := a.userRepo.Create(context.Background(), "Test", ulid.Make().String()+"@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("create test user: %s", err)
	}
	return user.ID
}

func TestGatewayTokenRoundTrip(t *testing.T) {
	a := newTestAuthService(t)
	ctx := context.Background()
	userID := createTestUser(t, a)

	secret, err := a.CreateGatewayToken(ctx, userID)
	if err != nil {
		t.Fatalf("create gateway token: %s", err)
	}

	got, err := a.VerifyGatewayToken(ctx, secret)
	if err != nil {
		t.Fatalf("verify gateway token: %s", err)
	}
	if got != userID {
		t.Fatalf("verify returned wrong user: got %s, want %s", got, userID)
	}
}

func TestGatewayTokenInvalid(t *testing.T) {
	a := newTestAuthService(t)
	ctx := context.Background()

	_, err := a.VerifyGatewayToken(ctx, "not-a-real-token")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestGatewayTokenDelete(t *testing.T) {
	a := newTestAuthService(t)
	ctx := context.Background()
	userID := createTestUser(t, a)

	secret, err := a.CreateGatewayToken(ctx, userID)
	if err != nil {
		t.Fatalf("create gateway token: %s", err)
	}
	if err := a.DeleteGatewayToken(ctx, secret); err != nil {
		t.Fatalf("delete gateway token: %s", err)
	}

	_, err = a.VerifyGatewayToken(ctx, secret)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials after delete, got %v", err)
	}
}

func TestGatewayTokenMultipleConcurrent(t *testing.T) {
	a := newTestAuthService(t)
	ctx := context.Background()
	userID := createTestUser(t, a)

	firstSecret, err := a.CreateGatewayToken(ctx, userID)
	if err != nil {
		t.Fatalf("create first gateway token: %s", err)
	}
	secondSecret, err := a.CreateGatewayToken(ctx, userID)
	if err != nil {
		t.Fatalf("create second gateway token: %s", err)
	}

	if _, err := a.VerifyGatewayToken(ctx, firstSecret); err != nil {
		t.Fatalf("verify first token: %s", err)
	}
	if _, err := a.VerifyGatewayToken(ctx, secondSecret); err != nil {
		t.Fatalf("verify second token: %s", err)
	}

	// deleting one device's token must not affect the other
	if err := a.DeleteGatewayToken(ctx, firstSecret); err != nil {
		t.Fatalf("delete first token: %s", err)
	}
	if _, err := a.VerifyGatewayToken(ctx, firstSecret); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected first token to be invalidated, got %v", err)
	}
	if _, err := a.VerifyGatewayToken(ctx, secondSecret); err != nil {
		t.Fatalf("verify second token after deleting first: %s", err)
	}
}

func TestGatewayTokenDeleteAll(t *testing.T) {
	a := newTestAuthService(t)
	ctx := context.Background()
	userID := createTestUser(t, a)

	firstSecret, err := a.CreateGatewayToken(ctx, userID)
	if err != nil {
		t.Fatalf("create first gateway token: %s", err)
	}
	secondSecret, err := a.CreateGatewayToken(ctx, userID)
	if err != nil {
		t.Fatalf("create second gateway token: %s", err)
	}

	if err := a.DeleteAllGatewayTokens(ctx, userID); err != nil {
		t.Fatalf("delete all gateway tokens: %s", err)
	}

	if _, err := a.VerifyGatewayToken(ctx, firstSecret); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected first token to be invalidated, got %v", err)
	}
	if _, err := a.VerifyGatewayToken(ctx, secondSecret); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected second token to be invalidated, got %v", err)
	}
}

func TestGatewayTokenExpired(t *testing.T) {
	a := newTestAuthService(t)
	ctx := context.Background()
	userID := createTestUser(t, a)

	secret := GenerateToken(64)
	if err := a.gatewayTokenRepo.Create(ctx, userID, hashTokenWeak(secret), -time.Minute); err != nil {
		t.Fatalf("create expired token: %s", err)
	}

	if _, err := a.VerifyGatewayToken(ctx, secret); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected expired token to be invalid, got %v", err)
	}
}
