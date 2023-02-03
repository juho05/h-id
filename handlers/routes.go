package handlers

import (
	"io/fs"
	"net/http"
	"time"

	"github.com/Bananenpro/log"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func (h *Handler) registerMiddlewares() {
	h.Router.Use(recoverPanic)
	h.Router.Use(middleware.RealIP)
	h.Router.Use(middleware.RequestID)
	h.Router.Use(middleware.Timeout(60 * time.Second))
	h.Router.Use(logRequest)
	h.Router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowCredentials: true,
		MaxAge:           int((15 * time.Minute).Seconds()),
	}))
}

func (h *Handler) RegisterRoutes() {
	if h.Router == nil {
		h.Router = chi.NewRouter()
	}
	h.registerMiddlewares()

	h.registerStaticRouts()
	h.Router.Route("/.well-known", h.wellKnownRoutes)

	h.Router.With(h.SessionManager.LoadAndSave).Get("/", h.newPage("index"))
	h.Router.With(h.SessionManager.LoadAndSave).With(csrf).Route("/user", h.userRoutes)
	h.Router.With(h.SessionManager.LoadAndSave).With(csrf).Route("/app", h.appRoutes)
	h.Router.With(h.SessionManager.LoadAndSave).Route("/oauth", h.oauthRoutes)
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
