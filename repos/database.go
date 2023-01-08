package repos

type DB interface {
	NewUserRepository() UserRepository
}

type Transaction interface {
	Commit() error
	Rollback() error
}
