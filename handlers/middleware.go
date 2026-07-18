package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/cors"
	"github.com/juho05/log"
	"github.com/justinas/nosurf"
	"github.com/oklog/ulid/v2"
	"github.com/sethvargo/go-limiter/httplimit"
	"github.com/sethvargo/go-limiter/memorystore"

	hid "github.com/juho05/h-id"

	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/services"
)

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusResponseWriter) WriteHeader(code int) {
	if s.status >= 200 {
		return
	}
	s.status = code
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
	handler.ExemptGlobs("/user/passkey/create/*", "/user/passkey/verify/*")
	handler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return handler
}

func (h *Handler) noauth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := h.SessionManager.Get(r.Context(), "authUserID").(ulid.ULID)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		redirect, _ := h.validRedirect(r.URL.Query().Get("redirect"))
		redirectQuery := ""
		if redirect != "" {
			redirectQuery = "?redirect=" + url.QueryEscape(redirect)
		}

		// Route incomplete accounts through the remaining login prerequisites (like the
		// auth middleware) before honoring the redirect. Otherwise a gateway login for a
		// not-yet-fully-set-up user dead-ends: no token can be issued, so the target
		// bounces back here and loops.
		confirmed, otpActive, hasRecovery, err := h.AuthService.CheckLoginPrerequisites(r.Context())
		if err != nil {
			h.SessionManager.Destroy(r.Context())
			next.ServeHTTP(w, r)
			return
		}
		switch {
		case !confirmed:
			http.Redirect(w, r, "/user/confirmEmail"+redirectQuery, http.StatusSeeOther)
			return
		case !otpActive:
			http.Redirect(w, r, "/user/2fa/otp/activate"+redirectQuery, http.StatusSeeOther)
			return
		case !hasRecovery:
			http.Redirect(w, r, "/user/2fa/recovery"+redirectQuery, http.StatusSeeOther)
			return
		}

		if !h.hasValidGatewayCookie(r) {
			if err := h.issueGatewayCookie(w, r, userID); err != nil {
				serverError(w, err)
				return
			}
		}
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
	})
}

func (h *Handler) gatewayAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectProto := r.Header.Get("X-Forwarded-Proto")
		redirectHost := r.Header.Get("X-Forwarded-Host")
		redirectURI := r.Header.Get("X-Forwarded-Uri")
		if !h.AuthGatewayService.IsAllowedDomain(redirectHost) {
			clientError(w, http.StatusForbidden)
			return
		}
		uri, err := url.Parse(redirectProto + "://" + redirectHost + redirectURI)
		if err != nil || !uri.IsAbs() || uri.Host != redirectHost || uri.RequestURI() != redirectURI {
			clientError(w, http.StatusBadRequest)
			return
		}
		loginURL := fmt.Sprintf("%s/user/login?redirect=%s", config.BaseURL(), url.QueryEscape(uri.String()))

		cookie, err := r.Cookie("h-id_gateway")
		if err != nil {
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
			return
		}
		userID, err := h.AuthService.VerifyGatewayToken(r.Context(), cookie.Value)
		if err != nil {
			if !errors.Is(err, services.ErrInvalidCredentials) {
				serverError(w, err)
				return
			}
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), services.AuthUserIDCtxKey{}, userID))
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := url.QueryEscape(r.URL.RequestURI())

		userID, ok := h.SessionManager.Get(r.Context(), "authUserID").(ulid.ULID)
		if !ok {
			http.Redirect(w, r, fmt.Sprintf("%s/user/login?redirect=%s", config.BaseURL(), redirect), http.StatusSeeOther)
			return
		}

		if !slices.Contains([]string{"/user/logout", "/user/confirmEmail", "/user/2fa/otp/activate", "/user/2fa/recovery"}, r.URL.Path) {
			confirmed, otpActive, hasRecovery, err := h.AuthService.CheckLoginPrerequisites(r.Context())
			if err != nil {
				h.SessionManager.Destroy(r.Context())
				http.Redirect(w, r, fmt.Sprintf("%s/user/login?redirect=%s", config.BaseURL(), redirect), http.StatusSeeOther)
				return
			}
			if !confirmed {
				http.Redirect(w, r, fmt.Sprintf("%s/user/confirmEmail?redirect=%s", config.BaseURL(), redirect), http.StatusSeeOther)
				return
			}
			if !otpActive {
				http.Redirect(w, r, fmt.Sprintf("%s/user/2fa/otp/activate?redirect=%s", config.BaseURL(), redirect), http.StatusSeeOther)
				return
			}
			if !hasRecovery {
				http.Redirect(w, r, fmt.Sprintf("%s/user/2fa/recovery?redirect=%s", config.BaseURL(), redirect), http.StatusSeeOther)
				return
			}
		}

		r = r.WithContext(context.WithValue(r.Context(), services.AuthUserIDCtxKey{}, userID))

		next.ServeHTTP(w, r)
	})
}

func (h *Handler) oauth(requiredScopes ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, scopes, err := h.AuthService.VerifyAccessToken(r.Context(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), requiredScopes)
			if err != nil {
				if errors.Is(err, services.ErrInvalidCredentials) {
					if r.Header.Get("Authorization") == "" {
						w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer scope=\"%s\" error=\"%s\"", strings.Join(requiredScopes, " "), "missing_token"))
					} else {
						w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer scope=\"%s\" error=\"%s\"", strings.Join(requiredScopes, " "), "invalid_token"))
					}
					clientError(w, http.StatusUnauthorized)
				} else if errors.Is(err, services.ErrInsufficientScope) {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer scope=\"%s\" error=\"%s\"", strings.Join(requiredScopes, " "), "insufficient_scope"))
					clientError(w, http.StatusForbidden)
				} else {
					serverError(w, err)
				}
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), services.AuthUserIDCtxKey{}, userID))
			r = r.WithContext(context.WithValue(r.Context(), services.AuthScopesCtxKey{}, scopes))
			next.ServeHTTP(w, r)
		})
	}
}

func (h *Handler) admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := h.AuthService.AuthenticatedUserID(r.Context())
		if userID == (ulid.ULID{}) {
			serverError(w, errors.New("admin middleware required auth middleware"))
			return
		}
		user, err := h.UserService.Find(r.Context(), userID)
		if err != nil {
			serverError(w, fmt.Errorf("admin middleware: %w", err))
			return
		}
		if !user.Admin {
			clientError(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func staticCache(maxAge time.Duration) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int64(maxAge.Seconds())))
			w.Header().Set("Last-Modified", hid.StartTime.Format(http.TimeFormat))
			if ifModSince, err := time.Parse(http.TimeFormat, r.Header.Get("If-Modified-Since")); err == nil && ifModSince.After(hid.StartTime) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.HCaptchaSiteKey() != "" {
			w.Header().Set("Content-Security-Policy", "default-src 'self';style-src 'self' https://hcaptcha.com https://*.hcaptcha.com;frame-src 'self' https://hcaptcha.com https://*.hcaptcha.com;script-src 'self' https://hcaptcha.com https://*.hcaptcha.com; connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com;")
		} else {
			w.Header().Set("Content-Security-Policy", "default-src 'self';style-src 'self';frame-src 'self';script-src 'self'; connect-src 'self';")
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		if strings.HasPrefix(r.URL.Path, "/user/") && strings.HasSuffix(r.URL.Path, "/picture") {
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
		} else {
			w.Header().Set("Cross-Origin-Resource-Policy", "same-site")
		}
		w.Header().Set("Permissions-Policy", "interest-cohort=()")
		w.Header().Set("Form-Action", "'self'")
		w.Header().Set("Base-Uri", "'none'")
		next.ServeHTTP(w, r)
	})
}

func corsHeaders(next http.Handler) http.Handler {
	handler := cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowCredentials: false,
		MaxAge:           int((15 * time.Minute).Seconds()),
	})
	return handler(next)
}

func rateLimit(tokens int, interval time.Duration) func(next http.Handler) http.Handler {
	store, err := memorystore.New(&memorystore.Config{
		Tokens:   uint64(tokens),
		Interval: interval,
	})
	if err != nil {
		panic("init rate limit store: " + err.Error())
	}
	var headers []string
	if config.TrustedProxyCount() > 0 {
		headers = append(headers, http.CanonicalHeaderKey("X-Forwarded-For"))
	}
	mware, err := httplimit.NewMiddleware(store, httplimit.IPKeyFunc(headers...))
	if err != nil {
		panic("init rate limit middleware: " + err.Error())
	}
	return func(next http.Handler) http.Handler {
		limited := mware.Handle(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if config.TrustedProxyCount() > 0 {
				normalizeXForwardedFor(r)
			}
			limited.ServeHTTP(w, r)
		})
	}
}

func normalizeXForwardedFor(r *http.Request) {
	values := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	clientIndex := len(values) - config.TrustedProxyCount()
	if clientIndex < 0 || clientIndex >= len(values) {
		r.Header.Del("X-Forwarded-For")
		return
	}
	r.Header.Set("X-Forwarded-For", strings.TrimSpace(values[clientIndex]))
}
