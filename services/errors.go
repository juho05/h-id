package services

import "errors"

var (
	ErrInvalidCredentials         = errors.New("invalid-credentials")
	ErrTimeout                    = errors.New("timeout")
	ErrInvalidRedirectURI         = errors.New("invalid-redirect-uri")
	ErrUnsupportedResponseType    = errors.New("unsupported-response-type")
	ErrInvalidScope               = errors.New("invalid-scope")
	ErrMissingRequiredSessionData = errors.New("missing-required-session-data")
	ErrReusedToken                = errors.New("reused-token")
	ErrInvalidGrant               = errors.New("invalid-grant")
	ErrUnsupportedGrantType       = errors.New("unsupported-grant-type")

	ErrInsufficientScope = errors.New("insufficient-scope")
)
