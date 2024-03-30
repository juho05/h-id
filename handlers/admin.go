package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/services"
	"github.com/juho05/log"
	"github.com/oklog/ulid/v2"
)

func (h *Handler) adminRoutes(r chi.Router) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/user", http.StatusTemporaryRedirect)
	})
	r.Get("/user", h.adminListUsers)
	r.Get("/user/{userID}", h.adminViewUser)
	r.Post("/user/{userID}/delete", h.adminDeleteUser)
	r.Get("/user/invite", h.newPage("adminInvite"))
	r.Post("/user/invite", h.adminInvite)
}

// GET /admin/user
func (h *Handler) adminListUsers(w http.ResponseWriter, r *http.Request) {
	repoUsers, err := h.UserService.FindAll(r.Context())
	if err != nil {
		serverError(w, fmt.Errorf("admin list users: %w", err))
		return
	}
	type user struct {
		ID   string
		Name string
	}
	users := make([]user, len(repoUsers))
	for i, u := range repoUsers {
		users[i] = user{
			ID:   u.ID.String(),
			Name: u.Name,
		}
	}
	type data struct {
		Users []user
	}
	h.Renderer.render(w, r, http.StatusOK, "listUsers", h.newTemplateDataWithData(r, data{
		Users: users,
	}))
}

// GET /admin/user/{userID}
func (h *Handler) adminViewUser(w http.ResponseWriter, r *http.Request) {
	userID, err := ulid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}
	repoUser, err := h.UserService.Find(r.Context(), userID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else {
			serverError(w, err)
		}
		return
	}
	type user struct {
		ID      string
		Name    string
		Email   string
		IsAdmin bool
	}
	h.Renderer.render(w, r, http.StatusOK, "user", h.newTemplateDataWithData(r, user{
		ID:      repoUser.ID.String(),
		Name:    repoUser.Name,
		Email:   repoUser.Email,
		IsAdmin: repoUser.Admin,
	}))
}

// POST /admin/user/{userID}/delete
func (h *Handler) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	userID, err := ulid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}
	user, err := h.UserService.Find(r.Context(), userID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else {
			serverError(w, err)
		}
		return
	}

	ok := h.verifyConfirmation(w, r, user.Name, true)
	if !ok {
		return
	}

	err = h.UserService.Delete(r.Context(), userID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else {
			serverError(w, err)
		}
		return
	}

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	go func() {
		subject, err := services.Translate(lang, "accountDeleted")
		if err != nil {
			log.Errorf("Failed to send account deleted notification: %w", err)
			return
		}
		err = h.EmailService.SendEmail(user.Email, subject, "accountDeleted", services.NewEmailTemplateData(user.Name, lang))
		if err != nil {
			log.Errorf("Failed to send account deleted notification: %w", err)
			return
		}
	}()

	if userID == h.AuthService.AuthenticatedUserID(r.Context()) {
		err := h.AuthService.Logout(r.Context())
		if err != nil {
			log.Errorf("Failed to logout user after delete: %w", err)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/user", http.StatusSeeOther)
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
	err := h.AuthService.SendInvitation(r.Context(), body.Email, lang, false)
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
