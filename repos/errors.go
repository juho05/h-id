package repos

import "errors"

var (
	ErrNoRecord       = errors.New("no matching record found")
	ErrDuplicateEmail = errors.New("duplicate email")
	ErrKeyExists      = errors.New("key exists")
)
