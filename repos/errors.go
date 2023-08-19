package repos

import "errors"

var (
	ErrNoRecord = errors.New("no matching record found")
	ErrExists   = errors.New("already exists")
)
