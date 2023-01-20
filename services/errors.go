package services

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTimeout            = errors.New("timeout")
)
