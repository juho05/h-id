package services

import (
	"context"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/juho05/h-id/repos"
	"github.com/juho05/log"
)

type webAuthnUser struct {
	user        *repos.UserModel
	credentials []webauthn.Credential
	userRepo    repos.UserRepository
}

func (a *authService) newWebAuthnUser(user *repos.UserModel) *webAuthnUser {
	return &webAuthnUser{
		user:        user,
		credentials: nil,
		userRepo:    a.userRepo,
	}
}

func (w *webAuthnUser) loadCredentials() {
	passkeys, err := w.userRepo.GetPasskeys(context.Background(), w.user.ID)
	if err != nil {
		w.credentials = make([]webauthn.Credential, 0)
		log.Errorf("Failed to load webauthn credentials: %w", err)
		return
	}
	w.credentials = make([]webauthn.Credential, len(passkeys))
	for i, p := range passkeys {
		w.credentials[i] = p.Credential
	}
}

func (w *webAuthnUser) WebAuthnID() []byte {
	return w.user.ID[:]
}

func (w *webAuthnUser) WebAuthnName() string {
	return w.user.Email
}

func (w *webAuthnUser) WebAuthnDisplayName() string {
	return w.user.Name
}

func (w *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	if w.credentials == nil {
		w.loadCredentials()
	}
	return w.credentials
}

func (w *webAuthnUser) WebAuthnIcon() string {
	return ""
}
