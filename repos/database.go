package repos

type DB interface {
	NewUserRepository() UserRepository
	NewSessionRepository() SessionRepository
}

type Transaction interface {
	Commit() error
	Rollback() error
}

type BaseModel struct {
	ID        string `db:"id"`
	CreatedAt int64  `db:"created_at"`
}
