package middlewares

import (
	"io"
	"net/http"
	"time"

	"github.com/Bananenpro/log"
)

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusResponseWriter) WriteHeader(code int) {
	if s.status < 200 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusResponseWriter) Write(b []byte) (int, error) {
	if s.status < 200 {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if s.status < 200 {
		s.WriteHeader(http.StatusOK)
	}
	return io.Copy(s.ResponseWriter, r)
}

func Logger(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		rw := &statusResponseWriter{ResponseWriter: w}
		start := time.Now()
		defer func() {
			log.Tracef("%s %s, status: %d %s, duration: %s", r.Method, r.URL.String(), rw.status, http.StatusText(rw.status), time.Since(start).String())
		}()
		next.ServeHTTP(rw, r)
	}
	return http.HandlerFunc(fn)
}
