package repos

import (
	"github.com/alexedwards/scs/v2"
)

type SessionModel struct {
	Token   string `db:"token"`
	Data    []byte `db:"data"`
	Expires int64  `db:"expires"`
}

type SessionRepository interface {
	scs.Store
	scs.CtxStore
	scs.IterableStore
	scs.IterableCtxStore
}
