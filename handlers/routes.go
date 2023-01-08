package handlers

import (
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/Bananenpro/h-id/handlers/middlewares"
)

func (h *Handler) RegisterMiddlewares() {
	h.Router.Use(middleware.RealIP)
	h.Router.Use(middleware.RequestID)
	h.Router.Use(middleware.Timeout(60 * time.Second))
	h.Router.Use(middlewares.Logger)
	h.Router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowCredentials: true,
		MaxAge:           int((15 * time.Minute).Seconds()),
	}))
	h.Router.Use(middleware.Recoverer)
}

func (g *Handler) RegisterRoutes() {
}
