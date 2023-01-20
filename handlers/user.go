package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/Bananenpro/h-id/repos"
	"github.com/Bananenpro/h-id/services"
)

func (h *Handler) userRoutes(r chi.Router) {
	r.Get("/signup", h.newPage("signup"))
	r.Post("/signup", h.userSignUp)
	r.Get("/login", h.userLoginPage)
	r.Post("/login", h.userLogin)

	r.With(h.auth).Get("/profile", h.userProfile)
}

// POST /user/signup
func (h *Handler) userSignUp(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name           string `form:"name" validate:"required,notblank,min=3,max=32"`
		Email          string `form:"email" validate:"required,email"`
		Password       string `form:"password" validate:"required,min=6,maxsize=72"`
		RepeatPassword string `form:"repeatPassword" validate:"required,eqfield=Password"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "signup", nil)
	if !ok {
		return
	}

	user, err := h.UserService.Create(r.Context(), body.Name, body.Email, body.Password)
	if err != nil {
		if errors.Is(err, repos.ErrDuplicateEmail) {
			data := h.newTemplateData(r)
			data.Errors = []string{"The user already exists."}
			data.Form = body
			h.Renderer.render(w, http.StatusUnprocessableEntity, "signup", data)
		} else {
			serverError(w, err)
		}
		return
	}

	h.SessionManager.Put(r.Context(), "email", user.Email)

	if user.EmailConfirmed {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/user/confirmEmail", http.StatusSeeOther)
	}
}

func (h *Handler) userLoginPage(w http.ResponseWriter, r *http.Request) {
	if redirect := r.URL.Query().Get("redirect"); redirect != "" {
		redirectUnescaped, err := url.QueryUnescape(redirect)
		if err == nil {
			u, err := url.Parse(redirectUnescaped)
			if err == nil {
				if u.IsAbs() {
					clientError(w, http.StatusBadRequest)
					return
				}
				h.SessionManager.Put(r.Context(), "loginRedirect", "/"+strings.TrimPrefix(redirectUnescaped, "/"))
			}
		}
	} else {
		h.SessionManager.Remove(r.Context(), "loginRedirect")
	}
	h.Renderer.render(w, http.StatusOK, "login", h.newTemplateData(r))
}

// POST /user/login
func (h *Handler) userLogin(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email    string `form:"email" validate:"required,notblank,email"`
		Password string `form:"password" validate:"required"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "login", nil)
	if !ok {
		return
	}

	err := h.AuthService.Login(r.Context(), body.Email, body.Password)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			data := h.newTemplateData(r)
			data.Errors = []string{"Invalid credentials."}
			data.Form = body
			h.Renderer.render(w, http.StatusUnauthorized, "login", data)
		} else {
			serverError(w, err)
		}
		return
	}

	if redirect := h.SessionManager.PopString(r.Context(), "loginRedirect"); redirect != "" {
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
}

// GET /user/profile
func (h *Handler) userProfile(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h.SessionManager.GetString(r.Context(), "authUserID")))
}
