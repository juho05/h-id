package handlers

import (
	"fmt"
	"net/http"
	"time"

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
	h.Router.Use(h.SessionManager.LoadAndSave)
	h.SessionManager.ErrorFunc = func(w http.ResponseWriter, _ *http.Request, err error) {
		serverError(w, fmt.Errorf("session load/save: %w", err))
	}
}

func (h *Handler) RegisterRoutes() {
	if h.Router == nil {
		h.Router = chi.NewRouter()
	}
	h.registerMiddlewares()
	h.Router.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(h.StaticFS))))
	h.Router.With(csrf).Route("/user", h.userRoutes)
	h.Router.With(csrf).Route("/app", h.appRoutes)
}
