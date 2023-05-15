package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	hid "github.com/juho05/h-id"
)

func (h *Handler) wellKnownRoutes(r chi.Router) {
	r.Get("/openid-configuration", h.openIDConfig)
}

func (h *Handler) openIDConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(hid.OpenIDConfiguration)
}
