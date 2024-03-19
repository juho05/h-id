package handlers

import (
	"io/fs"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/juho05/log"
)

func (h *Handler) registerMiddlewares() {
	h.Router.Use(recoverPanic)
	h.Router.Use(middleware.RealIP)
	h.Router.Use(middleware.RequestID)
	h.Router.Use(middleware.Timeout(60 * time.Second))
	h.Router.Use(logRequest)
	h.Router.Use(securityHeaders)
}

func (h *Handler) RegisterRoutes() {
	if h.Router == nil {
		h.Router = chi.NewRouter()
	}
	h.registerMiddlewares()

	h.registerStaticRouts()
	h.Router.Route("/.well-known", h.wellKnownRoutes)

	h.Router.With(h.SessionManager.LoadAndSave, csrf, h.auth).Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
	})
	h.Router.With(h.SessionManager.LoadAndSave, csrf).Route("/user", h.userRoutes)
	h.Router.With(h.SessionManager.LoadAndSave, csrf).Route("/app", h.appRoutes)
	h.Router.With(corsHeaders, h.SessionManager.LoadAndSave).Route("/oauth", h.oauthRoutes)
}

func (h *Handler) registerStaticRouts() {
	fonts, err := fs.Sub(h.StaticFS, "fonts")
	if err != nil {
		log.Fatalf("Failed to register fonts directory: %s", err)
	}
	h.Router.With(staticCache(8*7*24*time.Hour)).Handle("/static/fonts/*", http.StripPrefix("/static/fonts/", http.FileServer(http.FS(fonts))))

	img, err := fs.Sub(h.StaticFS, "img")
	if err != nil {
		log.Fatalf("Failed to register img directory: %s", err)
	}
	h.Router.With(staticCache(7*24*time.Hour)).Handle("/static/img/*", http.StripPrefix("/static/img/", http.FileServer(http.FS(img))))

	h.Router.With(staticCache(24*time.Hour)).Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(h.StaticFS))))
}
