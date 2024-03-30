package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/services"
)

func (h *Handler) adminRoutes(r chi.Router) {
	r.Get("/user", h.adminListUsers)
	r.Get("/user/{userID}", h.adminViewUser)
	r.Post("/user/{userID}/delete", h.adminDeleteUser)
	r.Get("/user/invite", h.newPage("adminInvite"))
	r.Post("/user/invite", h.adminInvite)
}

// GET /admin/user
func (h *Handler) adminListUsers(w http.ResponseWriter, r *http.Request) {

}

// GET /admin/user/{userID}
func (h *Handler) adminViewUser(w http.ResponseWriter, r *http.Request) {

}

// POST /admin/user/{userID}/delete
func (h *Handler) adminDeleteUser(w http.ResponseWriter, r *http.Request) {

}

// POST /admin/user/invite
func (h *Handler) adminInvite(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email string `form:"email" validate:"required,email"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "adminInvite", nil)
	if !ok {
		return
	}
	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	err := h.AuthService.SendInvitation(r.Context(), body.Email, lang)
	tmplData := h.newTemplateData(r)
	if err != nil {
		if errors.Is(err, repos.ErrExists) {
			lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
			tmplData.FieldErrors["Email"] = services.MustTranslate(lang, "emailAlreadyInUse")
			h.Renderer.render(w, r, http.StatusUnprocessableEntity, "adminInvite", tmplData)
		} else {
			serverError(w, err)
		}
		return
	}
	tmplData.Data = struct {
		Success bool
	}{
		Success: true,
	}
	h.Renderer.render(w, r, http.StatusOK, "adminInvite", tmplData)
}
