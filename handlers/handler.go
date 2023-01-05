package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Handler struct {
	Router chi.Router
}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Router.ServeHTTP(w, r)
}
