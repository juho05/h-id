package handlers

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/disintegration/imaging"
	"github.com/go-chi/chi/v5"

	"github.com/Bananenpro/h-id/config"
	"github.com/Bananenpro/h-id/repos"
	"github.com/Bananenpro/h-id/services"
)

func (h *Handler) userRoutes(r chi.Router) {
	r.Get("/signup", h.userSignUpPage)
	r.Post("/signup", h.userSignUp)
	r.Get("/login", h.userLoginPage)
	r.Post("/login", h.userLogin)
	r.With(h.auth).Post("/logout", h.userLogout)

	r.Get("/confirmEmail", h.userConfirmEmailPage)
	r.Post("/confirmEmail", h.userConfirmEmail)

	r.With(corsHeaders).Get("/{id}/picture", h.profilePicture)
	r.With(corsHeaders, h.oauth()).HandleFunc("/info", h.userInfo)

	r.With(h.auth).Get("/profile", h.userProfile)
	r.With(h.auth).Post("/profile", h.updateUserProfile)
}

func (h *Handler) userSignUpPage(w http.ResponseWriter, r *http.Request) {
	type tmplData struct {
		LoginRedirect string
	}
	data := tmplData{}
	if redirect := h.SessionManager.GetString(r.Context(), "loginRedirect"); redirect != "" {
		data.LoginRedirect = url.QueryEscape(redirect)
	}
	if config.HCaptchaSiteKey() != "" {
		w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
	}
	h.Renderer.render(w, http.StatusOK, "signup", h.newTemplateDataWithData(r, data))
}

// POST /user/signup
func (h *Handler) userSignUp(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name           string `form:"name" validate:"required,notblank,min=3,max=32"`
		Email          string `form:"email" validate:"required,email"`
		Password       string `form:"password" validate:"required,min=6,maxsize=72"`
		RepeatPassword string `form:"repeatPassword" validate:"required,eqfield=Password"`
	}
	type tmplData struct {
		LoginRedirect string
	}
	data := h.newTemplateDataWithData(r, tmplData{
		LoginRedirect: url.QueryEscape(h.SessionManager.GetString(r.Context(), "loginRedirect")),
	})
	body, ok := decodeAndValidateBodyWithCaptcha[request](h, w, r, "signup", &data)
	if !ok {
		return
	}

	user, err := h.UserService.Create(r.Context(), body.Name, body.Email, body.Password)
	if err != nil {
		if errors.Is(err, repos.ErrDuplicateEmail) {
			data.Errors = []string{"The user already exists."}
			data.Form = body
			if config.HCaptchaSiteKey() != "" {
				w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
			}
			h.Renderer.render(w, http.StatusUnprocessableEntity, "signup", data)
		} else {
			serverError(w, err)
		}
		return
	}

	h.SessionManager.Put(r.Context(), "email", user.Email)

	redirectQuery := ""
	if redirect := h.SessionManager.PopString(r.Context(), "loginRedirect"); redirect != "" {
		redirectQuery = "?redirect=" + url.QueryEscape(redirect)
	}
	http.Redirect(w, r, "/user/login"+redirectQuery, http.StatusSeeOther)
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
	data := h.newTemplateData(r)
	type form struct {
		Email string
	}
	data.Form = form{
		Email: h.SessionManager.PopString(r.Context(), "email"),
	}
	h.Renderer.render(w, http.StatusOK, "login", data)
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

// POST /user/logout
func (h *Handler) userLogout(w http.ResponseWriter, r *http.Request) {
	err := h.AuthService.Logout(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
		Picture       string `json:"picture"`
	}

	user, err := h.UserService.Find(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()))
	if err != nil {
		serverError(w, fmt.Errorf("userinfo endpoint: %w", err))
		return
	}

	resp := response{
		Subject: user.ID,
		Picture: config.BaseURL() + "/user/" + user.ID + "/picture",
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
	user, err := h.UserService.Find(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()))
	if err != nil {
		serverError(w, err)
		return
	}
	type userDTO struct {
		ID    string
		Name  string
		Email string
	}
	h.Renderer.render(w, http.StatusOK, "profile", h.newTemplateDataWithData(r, userDTO{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
	}))
}

// POST /user/profile
func (h *Handler) updateUserProfile(w http.ResponseWriter, r *http.Request) {
	user, err := h.UserService.Find(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()))
	if err != nil {
		serverError(w, err)
		return
	}

	type request struct {
		Name string `form:"name" validate:"required,notblank,min=3,max=32"`
	}
	type userDTO struct {
		ID    string
		Name  string
		Email string
	}
	tmplData := h.newTemplateDataWithData(r, userDTO{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
	})
	body, ok := decodeAndValidateBody[request](h, w, r, "profile", &tmplData)
	if !ok {
		return
	}

	err = h.UserService.Update(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()), body.Name)
	if err != nil {
		serverError(w, err)
		return
	}

	if pictureFile, pictureHeader, err := r.FormFile("profile_picture"); err == nil {
		if pictureHeader.Size > 10<<20 { // 10 MB
			tmplData.FieldErrors["ProfilePicture"] = "Profile picture size must not exceed 10 MB"
			h.Renderer.render(w, http.StatusUnprocessableEntity, "profile", tmplData)
			return
		}

		mimeType, _, err := mime.ParseMediaType(pictureHeader.Header.Get("Content-Type"))
		if err != nil || (mimeType != "image/jpeg" && mimeType != "image/png" && mimeType != "image/gif") {
			tmplData.FieldErrors["ProfilePicture"] = "Profile picture must be in JPEG, PNG or GIF format"
			h.Renderer.render(w, http.StatusUnprocessableEntity, "profile", tmplData)
			return
		}

		img, err := imaging.Decode(io.LimitReader(pictureFile, 10<<20), imaging.AutoOrientation(true))
		if err != nil {
			clientError(w, http.StatusBadRequest)
			return
		}

		err = h.UserService.SetProfilePicture(user.ID, img)
		if err != nil {
			serverError(w, err)
			return
		}
	}

	http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
}

func (h *Handler) profilePicture(w http.ResponseWriter, r *http.Request) {
	size := 512
	if s, err := strconv.Atoi(r.URL.Query().Get("size")); err == nil {
		size = s
	}
	if size > config.ProfilePictureSize() {
		size = config.ProfilePictureSize()
	}

	userID := chi.URLParam(r, "id")

	etag := h.UserService.ProfilePictureETag(userID, size)
	if matchETagHeader(etag, r.Header.Get("If-None-Match"), true) {
		clientError(w, http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", fmt.Sprintf("W/\"%s\"", etag))
	w.WriteHeader(http.StatusOK)
	h.UserService.LoadProfilePicture(userID, size, w)
}
