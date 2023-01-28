package handlers

import (
	"errors"
	"fmt"
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

	r.Get("/confirmEmail", h.userConfirmEmailPage)
	r.Post("/confirmEmail", h.userConfirmEmail)

	r.With(h.oauth()).HandleFunc("/info", h.userInfo)

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
		u, err := url.Parse(redirect)
		if err == nil {
			if u.IsAbs() {
				clientError(w, http.StatusBadRequest)
				return
			}
			h.SessionManager.Put(r.Context(), "loginRedirect", "/"+strings.TrimPrefix(redirect, "/"))
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

// GET /user/confirmEmail
func (h *Handler) userConfirmEmailPage(w http.ResponseWriter, r *http.Request) {
	if redirect := r.URL.Query().Get("redirect"); redirect != "" {
		u, err := url.Parse(redirect)
		if err == nil {
			if u.IsAbs() {
				clientError(w, http.StatusBadRequest)
				return
			}
			h.SessionManager.Put(r.Context(), "confirmEmailRedirect", "/"+strings.TrimPrefix(redirect, "/"))
		}
	} else {
		h.SessionManager.Remove(r.Context(), "confirmEmailRedirect")
	}

	user, ok := h.authUser(w, r)
	if !ok {
		return
	}

	if user.EmailConfirmed {
		if redirect := h.SessionManager.PopString(r.Context(), "confirmEmailRedirect"); redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
		return
	}

	err := h.AuthService.SendConfirmEmail(r.Context(), user)
	if err != nil && !errors.Is(err, services.ErrTimeout) {
		serverError(w, err)
		return
	}

	h.Renderer.render(w, http.StatusOK, "confirmEmail", h.newTemplateData(r))
}

// POST /user/confirmEmail
func (h *Handler) userConfirmEmail(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Code string `form:"code" validate:"required,numeric,len=6"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "confirmEmail", nil)
	if !ok {
		return
	}

	userID := h.AuthService.AuthenticatedUserID(r.Context())
	if userID == "" {
		http.Redirect(w, r, fmt.Sprintf("/user/login?redirect=%s", url.QueryEscape(r.URL.Path)), http.StatusSeeOther)
		return
	}

	err := h.AuthService.ConfirmEmail(r.Context(), userID, body.Code)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			data := h.newTemplateData(r)
			data.Errors = []string{"Invalid credentials."}
			data.Form = body
			h.Renderer.render(w, http.StatusUnauthorized, "confirmEmail", data)
		} else {
			serverError(w, err)
		}
		return
	}

	if redirect := h.SessionManager.PopString(r.Context(), "confirmEmailRedirect"); redirect != "" {
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
}

// GET/POST /user/info
func (h *Handler) userInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		clientError(w, http.StatusMethodNotAllowed)
		return
	}
	type response struct {
		Subject       string `json:"sub"`
		Name          string `json:"name,omitempty"`
		Email         string `json:"email,omitempty"`
		EmailVerified bool   `json:"email_verified,omitempty"`
	}

	user, err := h.UserService.Find(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()))
	if err != nil {
		serverError(w, fmt.Errorf("userinfo endpoint: %w", err))
		return
	}

	resp := response{
		Subject: user.ID,
	}
	for _, scope := range h.AuthService.AuthorizedScopes(r.Context()) {
		switch scope {
		case "profile":
			resp.Name = user.Name
		case "email":
			resp.Email = user.Email
			resp.EmailVerified = user.EmailConfirmed
		}
	}
	respondJSON(w, http.StatusOK, resp)
}

// GET /user/profile
func (h *Handler) userProfile(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h.AuthService.AuthenticatedUserID(r.Context())))
}
