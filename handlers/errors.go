package handlers

import "errors"

var (
	ErrInvalidFields      = errors.New("invalid-fields")
	ErrUserExists         = errors.New("user-exists")
	ErrInvalidCredentials = errors.New("invalid-credentials")
)
