package handlers

import (
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) authGatewayRoutes(r chi.Router) {
	r.Get("/verify", h.authGatewayVerify)
}

// GET /gateway/verify
func (h *Handler) authGatewayVerify(w http.ResponseWriter, r *http.Request) {
	redirectProto := r.Header.Get("X-Forwarded-Proto")
	redirectHost := r.Header.Get("X-Forwarded-Host")
	redirectMethod := r.Header.Get("X-Forwarded-Method")
	redirectURLStr := r.Header.Get("X-Forwarded-Uri")
	if redirectProto == "" || redirectHost == "" || redirectMethod == "" || redirectURLStr == "" {
		clientError(w, http.StatusBadRequest)
		return
	}
	redirectURL, err := url.Parse(redirectProto + "://" + redirectHost + redirectURLStr)
	if err != nil || !redirectURL.IsAbs() || redirectURL.Host != redirectHost || redirectURL.RequestURI() != redirectURLStr {
		clientError(w, http.StatusBadRequest)
		return
	}
	userID := h.AuthService.AuthenticatedUserID(r.Context())
	if !h.AuthGatewayService.IsAuthorized(userID, redirectURL.Hostname()) {
		clientError(w, http.StatusForbidden)
		return
	}
	w.Header().Add("Remote-User", userID.String())
	w.WriteHeader(http.StatusOK)
}
