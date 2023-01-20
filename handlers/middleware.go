package handlers

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Bananenpro/log"
	"github.com/justinas/nosurf"
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

func logRequest(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		rw := &statusResponseWriter{ResponseWriter: w}
		start := time.Now()
		defer func() {
			u := r.URL
			u.RawQuery = ""
			u.RawFragment = ""
			log.Tracef("%s %s, status: %d %s, duration: %s", r.Method, u.String(), rw.status, http.StatusText(rw.status), time.Since(start).String())
		}()
		next.ServeHTTP(rw, r)
	}
	return http.HandlerFunc(fn)
}

func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				if e, ok := err.(error); ok && errors.Is(e, http.ErrAbortHandler) {
					panic(err)
				}
				w.Header().Set("Connection", "close")
				serverError(w, fmt.Errorf("%v", err))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func csrf(next http.Handler) http.Handler {
	handler := nosurf.New(next)
	handler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return handler
}

func (h *Handler) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := h.SessionManager.GetString(r.Context(), "authUserID")
		if userID == "" {
			http.Redirect(w, r, fmt.Sprintf("/user/login?redirect=%s", url.QueryEscape(r.URL.Path)), http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}
