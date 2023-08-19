package repos

import (
	"time"

	"github.com/alexedwards/scs/v2"
)

type SessionModel struct {
	Token   string
	Data    []byte
	Expires time.Time
}

type SessionRepository interface {
	scs.Store
	scs.CtxStore
	scs.IterableStore
	scs.IterableCtxStore
}
