package repos

import "time"

type DB interface {
	NewUserRepository() UserRepository
}

type Transaction interface {
	Commit() error
	Rollback() error
}

type BaseModel struct {
	ID        string    `db:"id"`
	CreatedAt time.Time `db:"created_at"`
}
