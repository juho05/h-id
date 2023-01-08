package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Bananenpro/h-id/services"
)

type Handler struct {
	Router      chi.Router
	AuthService services.AuthService
	UserService services.UserService
}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Router.ServeHTTP(w, r)
}
