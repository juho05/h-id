package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"image/jpeg"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/disintegration/imaging"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"

	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/services"
	"github.com/juho05/log"
)

func (h *Handler) userRoutes(r chi.Router) {
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/user/2fa") {
				h.SessionManager.Remove(r.Context(), "validPassword")
			}
			next.ServeHTTP(w, r)
		})
	})
	r.With(h.noauth).Get("/signup", h.userSignUpPage)
	r.With(h.noauth, rateLimit(1, time.Second)).Post("/signup", h.userSignUp)
	r.With(h.noauth).Get("/login", h.userLoginPage)
	r.With(h.noauth, rateLimit(2, 1*time.Second)).Post("/login", h.userLogin)
	r.With(h.noauth).Get("/forgotPassword", h.forgotPasswordPage)
	r.With(h.noauth, rateLimit(3, 20*time.Second)).Post("/forgotPassword", h.forgotPassword)
	r.With(h.noauth).Get("/resetPassword", h.resetPasswordPage)
	r.With(h.noauth, rateLimit(2, 10*time.Second)).Post("/resetPassword", h.resetPassword)
	r.With(h.auth).Post("/logout", h.userLogout)

	r.With(h.auth).Get("/confirmEmail", h.userConfirmEmailPage)
	r.With(h.auth, rateLimit(2, time.Second)).Post("/confirmEmail", h.userConfirmEmail)

	r.Get("/2fa/otp/activate", h.userActivateOTPPage)
	r.With(rateLimit(2, time.Second)).Post("/2fa/otp/activate", h.userActivateOTP)
	r.Get("/2fa/otp/activate/qr", h.userActivateOTPQRCode)
	r.With(h.auth).Get("/2fa/otp/reset", h.newPage("resetOTP"))
	r.With(h.auth, rateLimit(2, time.Second)).Post("/2fa/otp/reset", h.resetOTP)

	r.With(h.auth).Get("/2fa/recovery", h.recoveryCodesPage)
	r.With(h.auth).Post("/2fa/recovery", h.recoveryCodes)
	r.With(h.auth).Get("/2fa/recovery/reset", h.newPage("resetRecoveryCodes"))
	r.With(h.auth, rateLimit(2, time.Second)).Post("/2fa/recovery/reset", h.resetRecoveryCodes)

	r.With(h.noauth).Get("/2fa/otp/verify", h.verifyOTPPage)
	r.With(h.noauth, rateLimit(2, time.Second)).Post("/2fa/otp/verify", h.verifyOTP)

	r.With(h.auth).Get("/passkey", h.listPasskeys)
	r.With(h.auth).Get("/passkey/{passkeyID}", h.getPasskey)
	r.With(h.auth).Post("/passkey/{passkeyID}/update", h.updatePasskey)
	r.With(h.auth).Post("/passkey/{passkeyID}/delete", h.deletePasskey)
	r.With(h.auth).Get("/passkey/create", h.newPage("createPasskey"))
	r.With(h.auth).Post("/passkey/create/begin", h.createPasskeyBegin)
	r.With(h.auth).Post("/passkey/create/finish", h.createPasskeyFinish)

	r.With(h.noauth).Post("/passkey/verify/begin", h.verifyPasskeyBegin)
	r.With(h.noauth).Post("/passkey/verify/finish", h.verifyPasskeyFinish)

	r.With(corsHeaders).Get("/{id}/picture", h.profilePicture)
	r.With(corsHeaders, h.oauth()).HandleFunc("/info", h.userInfo)

	r.With(h.auth).Get("/changeEmail", h.changeEmailPage)
	r.With(h.auth, rateLimit(2, time.Second)).Post("/changeEmail", h.changeEmail)
	r.With(h.auth, rateLimit(2, 20*time.Second)).Get("/updateEmail", h.updateEmail)
	r.With(h.auth).Get("/profile", h.userProfile)
	r.With(h.auth).Post("/profile", h.updateUserProfile)
}

func (h *Handler) userSignUpPage(w http.ResponseWriter, r *http.Request) {
	type data struct {
		LoginRedirect string
	}
	tmplData := h.newTemplateData(r)
	if redirect := h.getRedirect(r, "login"); redirect != "" {
		tmplData.Data = data{
			LoginRedirect: redirect,
		}
	}
	if config.HCaptchaSiteKey() != "" {
		w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
	}
	query := r.URL.Query()
	type form struct {
		Name        string
		Email       string
		InviteToken string
	}
	tmplData.Form = form{
		Email:       query.Get("email"),
		InviteToken: query.Get("invitation"),
	}
	h.Renderer.render(w, r, http.StatusOK, "signup", tmplData)
}

// POST /user/signup
func (h *Handler) userSignUp(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name           string `form:"name" validate:"required,notblank,min=3,max=32"`
		Email          string `form:"email" validate:"required,email"`
		Password       string `form:"password" validate:"required,min=6,maxsize=72"`
		RepeatPassword string `form:"repeatPassword" validate:"required,eqfield=Password"`
		InviteToken    string `form:"invite"`
	}
	type tmplData struct {
		LoginRedirect string
	}
	data := h.newTemplateDataWithData(r, tmplData{
		LoginRedirect: h.getRedirect(r, "login"),
	})
	body, ok := decodeAndValidateBodyWithCaptcha[request](h, w, r, "signup", &data)
	if !ok {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Email = strings.TrimSpace(body.Email)

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	if body.InviteToken != "" || config.InviteOnly() {
		err := h.AuthService.VerifyInvitationToken(r.Context(), body.Email, body.InviteToken)
		if err != nil {
			if !errors.Is(err, services.ErrInvalidCredentials) {
				serverError(w, err)
				return
			}
			if config.InviteOnly() {
				data.Form = body
				data.Errors = append(data.Errors, services.MustTranslate(lang, "inviteOnlyInvalidToken"))
				h.Renderer.render(w, r, http.StatusUnprocessableEntity, "signup", data)
				return
			}
		}
	}

	user, err := h.UserService.Create(r.Context(), body.Name, body.Email, body.Password)
	if err != nil {
		if errors.Is(err, repos.ErrExists) {
			data.Errors = []string{"The user already exists."}
			data.Form = body
			if config.HCaptchaSiteKey() != "" {
				w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
			}
			h.Renderer.render(w, r, http.StatusUnprocessableEntity, "signup", data)
		} else {
			serverError(w, err)
		}
		return
	}

	err = h.AuthService.Login(r.Context(), user.ID)
	if err != nil {
		serverError(w, err)
		return
	}

	h.redirect(w, r, "login")
}

func (h *Handler) userLoginPage(w http.ResponseWriter, r *http.Request) {
	h.storeRedirect(r, "login")
	data := h.newTemplateData(r)
	type form struct {
		Email string
	}
	data.Form = form{
		Email: h.SessionManager.PopString(r.Context(), "email"),
	}
	h.Renderer.render(w, r, http.StatusOK, "login", data)
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

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))

	user, err := h.AuthService.VerifyUsernamePassword(r.Context(), body.Email, body.Password)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			data := h.newTemplateData(r)
			e, _ := services.Translate(lang, "invalidCredentials")
			data.Errors = []string{e}
			data.Form = body
			h.Renderer.render(w, r, http.StatusUnauthorized, "login", data)
		} else {
			serverError(w, err)
		}
		return
	}
	if !user.OTPActive {
		redirectQuery := ""
		if redirect := h.popRedirect(r, "login"); redirect != "" {
			redirectQuery = "?redirect=" + url.QueryEscape(redirect)
		}
		http.Redirect(w, r, "/user/2fa/otp/activate"+redirectQuery, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/user/2fa/otp/verify", http.StatusSeeOther)
	}
}

// GET /user/forgotPassword
func (h *Handler) forgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	success := h.SessionManager.PopString(r.Context(), "forgotPasswordSuccess")
	success, _ = services.Translate(lang, success)
	erro := h.SessionManager.PopString(r.Context(), "forgotPasswordError")
	erro, _ = services.Translate(lang, erro)
	if config.HCaptchaSiteKey() != "" {
		w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
	}
	type data struct {
		Success string
	}
	tmplData := h.newTemplateDataWithData(r, data{
		Success: success,
	})
	if erro != "" {
		tmplData.Errors = append(tmplData.Errors, erro)
	}
	h.Renderer.render(w, r, http.StatusOK, "forgotPassword", tmplData)
}

// POST /user/forgotPassword
func (h *Handler) forgotPassword(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email string `form:"email" validate:"required,email"`
	}
	body, ok := decodeAndValidateBodyWithCaptcha[request](h, w, r, "forgotPassword", nil)
	if !ok {
		return
	}

	if config.HCaptchaSiteKey() != "" {
		w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
	}

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	err := h.AuthService.RequestForgotPassword(r.Context(), lang, body.Email)
	if err != nil {
		if errors.Is(err, services.ErrTimeout) {
			h.SessionManager.Put(r.Context(), "forgotPasswordError", "forgotPasswordTimeout")
			http.Redirect(w, r, "/user/forgotPassword", http.StatusSeeOther)
		} else {
			serverError(w, err)
		}
		return
	}
	h.SessionManager.Put(r.Context(), "forgotPasswordSuccess", "resetLinkRequested")
	http.Redirect(w, r, "/user/forgotPassword", http.StatusSeeOther)
}

// GET /user/resetPassword
func (h *Handler) resetPasswordPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	type data struct {
		Token string
	}
	tmplData := h.newTemplateData(r)
	tmplData.Form = data{
		Token: token,
	}
	h.Renderer.render(w, r, http.StatusOK, "resetPassword", tmplData)
}

// POST /user/resetPassword
func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Token          string `form:"token" validate:"required"`
		Password       string `form:"password" validate:"required,min=6,maxsize=72"`
		RepeatPassword string `form:"repeatPassword" validate:"required,eqfield=Password"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "resetPassword", nil)
	if !ok {
		return
	}

	err := h.AuthService.ResetPassword(r.Context(), body.Token, body.Password)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
			data := h.newTemplateData(r)
			e, _ := services.Translate(lang, "expiredPasswordResetToken")
			data.Errors = []string{e}
			data.Form = body
			h.Renderer.render(w, r, http.StatusUnauthorized, "resetPassword", data)
		} else {
			serverError(w, err)
		}
		return
	}

	http.Redirect(w, r, "/user/login", http.StatusSeeOther)
}

func (h *Handler) verifyOTPPage(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.SessionManager.Get(r.Context(), "validPassword").(ulid.ULID)
	if !ok || userID == (ulid.ULID{}) {
		redirectQuery := ""
		if redirect := h.popRedirect(r, "login"); redirect != "" {
			redirectQuery = "?redirect=" + url.QueryEscape(redirect)
		}
		http.Redirect(w, r, "/user/login"+redirectQuery, http.StatusSeeOther)
		return
	}
	active, err := h.AuthService.IsOTPActive(r.Context(), userID)
	if err != nil {
		serverError(w, err)
		return
	}
	remember2FAErr := h.AuthService.VerifyRemember2FACookie(r.Context(), userID, r)
	if !active || remember2FAErr == nil {
		err = h.AuthService.Login(r.Context(), userID)
		if err != nil {
			serverError(w, err)
			return
		}
		h.redirect(w, r, "login")
		return
	}
	h.Renderer.render(w, r, http.StatusOK, "verifyOTP", h.newTemplateData(r))
}

// POST /user/2fa/otp/verify
func (h *Handler) verifyOTP(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Code string `form:"code" validate:"required,min=6"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "verifyOTP", nil)
	if !ok {
		return
	}

	userID, ok := h.SessionManager.Get(r.Context(), "validPassword").(ulid.ULID)
	if !ok || userID == (ulid.ULID{}) {
		redirectQuery := ""
		if redirect := h.popRedirect(r, "login"); redirect != "" {
			redirectQuery = "?redirect=" + url.QueryEscape(redirect)
		}
		http.Redirect(w, r, "/user/login"+redirectQuery, http.StatusSeeOther)
		return
	}

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))

	err := h.AuthService.VerifyOTPCode(r.Context(), userID, body.Code)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			data := h.newTemplateData(r)
			e, _ := services.Translate(lang, "invalidCredentials")
			data.Errors = []string{e}
			data.Form = body
			h.Renderer.render(w, r, http.StatusUnauthorized, "verifyOTP", data)
		} else {
			serverError(w, err)
		}
		return
	}

	err = h.AuthService.Login(r.Context(), userID)
	if err != nil {
		serverError(w, err)
		return
	}

	remember2FACookie, err := h.AuthService.CreateRemember2FACookie(r.Context(), userID)
	if err != nil {
		serverError(w, err)
		return
	}
	http.SetCookie(w, remember2FACookie)

	h.redirect(w, r, "login")
}

// GET /user/passkey
func (h *Handler) listPasskeys(w http.ResponseWriter, r *http.Request) {
	type passkey struct {
		ID   string
		Name string
	}
	type data struct {
		Passkeys []passkey
	}
	passkeys, err := h.UserService.GetPasskeys(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()))
	if err != nil {
		serverError(w, err)
		return
	}
	pkeys := make([]passkey, len(passkeys))
	for i, p := range passkeys {
		pkeys[i] = passkey{
			ID:   p.ID.String(),
			Name: p.Name,
		}
	}
	h.Renderer.render(w, r, http.StatusOK, "passkeys", h.newTemplateDataWithData(r, data{
		Passkeys: pkeys,
	}))
}

// GET /user/passkey/{passkeyID}
func (h *Handler) getPasskey(w http.ResponseWriter, r *http.Request) {
	passkeyID, err := ulid.Parse(chi.URLParam(r, "passkeyID"))
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}
	passkey, err := h.UserService.GetPasskey(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()), passkeyID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else {
			serverError(w, err)
		}
		return
	}
	type data struct {
		ID        string
		CreatedAt string
	}
	type form struct {
		Name string
	}
	tmplData := h.newTemplateDataWithData(r, data{
		ID:        passkey.ID.String(),
		CreatedAt: passkey.CreatedAt.Format(time.DateTime + " MST"),
	})
	tmplData.Form = form{
		Name: passkey.Name,
	}
	h.Renderer.render(w, r, http.StatusOK, "passkey", tmplData)
}

// POST /user/passkey/{passkeyID}/update
func (h *Handler) updatePasskey(w http.ResponseWriter, r *http.Request) {
	passkeyID, err := ulid.Parse(chi.URLParam(r, "passkeyID"))
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}
	passkey, err := h.UserService.GetPasskey(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()), passkeyID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else {
			serverError(w, err)
		}
		return
	}
	type data struct {
		ID        string
		CreatedAt string
	}
	tmplData := h.newTemplateDataWithData(r, data{
		ID:        passkey.ID.String(),
		CreatedAt: passkey.CreatedAt.Format(time.DateTime + " MST"),
	})
	type request struct {
		Name string `form:"name" validate:"required,notblank,min=3,max=32"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "passkey", &tmplData)
	if !ok {
		return
	}

	err = h.UserService.UpdatePasskey(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()), passkeyID, body.Name)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else {
			serverError(w, err)
		}
		return
	}

	http.Redirect(w, r, "/user/passkey/"+passkeyID.String(), http.StatusSeeOther)
}

// POST /user/passkey/{passkeyID}/delete
func (h *Handler) deletePasskey(w http.ResponseWriter, r *http.Request) {
	passkeyID, err := ulid.Parse(chi.URLParam(r, "passkeyID"))
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}
	passkey, err := h.UserService.GetPasskey(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()), passkeyID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else {
			serverError(w, err)
		}
		return
	}
	ok := h.verifyConfirmation(w, r, passkey.Name, false)
	if !ok {
		return
	}
	err = h.UserService.DeletePasskey(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()), passkeyID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else {
			serverError(w, err)
		}
		return
	}
	http.Redirect(w, r, "/user/passkey", http.StatusSeeOther)
}

// POST /user/passkey/create/begin
func (h *Handler) createPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name     string `form:"name" validate:"required,notblank,min=3,max=32"`
		Password string `form:"password" validate:"required"`
	}
	var body request
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	if err := validate.Struct(body); err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}
	user, err := h.UserService.Find(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()))
	if err != nil {
		serverError(w, err)
		return
	}
	options, err := h.AuthService.PasskeyBeginRegistration(r.Context(), user, body.Password, body.Name)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			clientError(w, http.StatusUnauthorized)
		} else {
			serverError(w, err)
		}
		return
	}
	respondJSON(w, http.StatusOK, options)
}

// POST /user/passkey/create/finish
func (h *Handler) createPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	user, err := h.UserService.Find(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()))
	if err != nil {
		serverError(w, err)
		return
	}
	err = h.AuthService.PasskeyFinishRegistration(r.Context(), user, r)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			clientError(w, http.StatusUnauthorized)
		} else {
			serverError(w, err)
		}
		return
	}
	respondJSON(w, http.StatusCreated, struct{}{})
}

// POST /user/passkey/verify/begin
func (h *Handler) verifyPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	assertion, err := h.AuthService.PasskeyBeginLogin(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, assertion)
}

// POST /user/passkey/verify/finish
func (h *Handler) verifyPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	user, err := h.AuthService.PasskeyFinishLogin(r.Context(), r)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			clientError(w, http.StatusUnauthorized)
		} else {
			serverError(w, err)
		}
		return
	}
	err = h.AuthService.Login(r.Context(), user.ID)
	if err != nil {
		serverError(w, err)
		return
	}
	type response struct {
		Redirect string `json:"redirect"`
	}
	redirect := config.BaseURL()
	if r := h.popRedirect(r, "login"); r != "" {
		redirect = r
	}
	respondJSON(w, http.StatusOK, response{
		Redirect: redirect,
	})
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
	h.storeRedirect(r, "confirmEmail")
	user, ok := h.authUser(w, r)
	if !ok {
		return
	}

	if user.EmailConfirmed {
		h.redirect(w, r, "confirmEmail")
		return
	}

	err := h.AuthService.SendConfirmEmail(r, r.Context(), user)
	if err != nil && !errors.Is(err, services.ErrTimeout) {
		serverError(w, err)
		return
	}

	h.Renderer.render(w, r, http.StatusOK, "confirmEmail", h.newTemplateData(r))
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
	if userID == (ulid.ULID{}) {
		http.Redirect(w, r, fmt.Sprintf("/user/login?redirect=%s", url.QueryEscape(r.URL.Path)), http.StatusSeeOther)
		return
	}

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	err := h.AuthService.ConfirmEmail(r.Context(), userID, body.Code)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			data := h.newTemplateData(r)
			e, _ := services.Translate(lang, "invalidCredentials")
			data.Errors = []string{e}
			data.Form = body
			h.Renderer.render(w, r, http.StatusUnauthorized, "confirmEmail", data)
		} else {
			serverError(w, err)
		}
		return
	}

	h.redirect(w, r, "confirmEmail")
}

// GET/POST /user/info
func (h *Handler) userInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		clientError(w, http.StatusMethodNotAllowed)
		return
	}
	type response struct {
		Subject       ulid.ULID `json:"sub"`
		Name          string    `json:"name,omitempty"`
		Email         string    `json:"email,omitempty"`
		EmailVerified bool      `json:"email_verified,omitempty"`
		Picture       string    `json:"picture"`
	}

	user, err := h.UserService.Find(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()))
	if err != nil {
		serverError(w, fmt.Errorf("userinfo endpoint: %w", err))
		return
	}

	resp := response{
		Subject: user.ID,
		Picture: config.BaseURL() + "/user/" + user.ID.String() + "/picture",
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

// GET /user/2fa/otp/activate
func (h *Handler) userActivateOTPPage(w http.ResponseWriter, r *http.Request) {
	h.storeRedirect(r, "activateOTP")

	userID := h.AuthService.AuthenticatedUserID(r.Context())
	if userID == (ulid.ULID{}) {
		var ok bool
		userID, ok = h.SessionManager.Get(r.Context(), "validPassword").(ulid.ULID)
		if !ok || userID == (ulid.ULID{}) {
			h.redirect(w, r, "activateOTP")
			return
		}
	}
	user, err := h.UserService.Find(r.Context(), userID)
	if err != nil {
		serverError(w, err)
		return
	}

	if user.OTPActive {
		h.redirect(w, r, "activateOTP")
		return
	}

	key, err := h.AuthService.GenerateOTPKey(r.Context(), user)
	if err != nil {
		serverError(w, err)
		return
	}
	type response struct {
		Secret string
	}
	tmplData := h.newTemplateData(r)
	tmplData.Form = response{
		Secret: key.Secret(),
	}
	h.Renderer.render(w, r, http.StatusOK, "activateOTP", tmplData)
}

// POST /user/2fa/otp/activate
func (h *Handler) userActivateOTP(w http.ResponseWriter, r *http.Request) {
	userID := h.AuthService.AuthenticatedUserID(r.Context())
	if userID == (ulid.ULID{}) {
		var ok bool
		userID, ok = h.SessionManager.Get(r.Context(), "validPassword").(ulid.ULID)
		if !ok || userID == (ulid.ULID{}) {
			h.redirect(w, r, "activateOTP")
			return
		}
	}

	type request struct {
		Secret string `form:"secret" validate:"required"`
		Code   string `form:"code" validate:"required,numeric,len=6"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "activateOTP", nil)
	if !ok {
		return
	}

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	err := h.AuthService.ActivateOTPKey(r.Context(), userID, body.Code)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			data := h.newTemplateData(r)
			e, _ := services.Translate(lang, "invalidCredentials")
			data.Errors = []string{e}
			data.Form = body
			h.Renderer.render(w, r, http.StatusUnauthorized, "activateOTP", data)
		} else {
			serverError(w, err)
		}
		return
	}

	if h.AuthService.AuthenticatedUserID(r.Context()) == (ulid.ULID{}) {
		err = h.AuthService.Login(r.Context(), userID)
		if err != nil {
			serverError(w, err)
			return
		}
	}

	h.redirect(w, r, "activateOTP")
}

// GET /user/2fa/otp/activate/qr
func (h *Handler) userActivateOTPQRCode(w http.ResponseWriter, r *http.Request) {
	userID := h.AuthService.AuthenticatedUserID(r.Context())
	if userID == (ulid.ULID{}) {
		var ok bool
		userID, ok = h.SessionManager.Get(r.Context(), "validPassword").(ulid.ULID)
		if !ok || userID == (ulid.ULID{}) {
			clientError(w, http.StatusUnauthorized)
			return
		}
	}
	user, err := h.UserService.Find(r.Context(), userID)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusUnauthorized)
		} else {
			serverError(w, err)
		}
		return
	}
	if user.OTPActive {
		clientError(w, http.StatusForbidden)
		return
	}

	sizeStr := r.URL.Query().Get("size")
	size := 500
	if sizeStr != "" {
		size, err = strconv.Atoi(sizeStr)
		if err != nil || size < 1 || size > 2048 {
			clientError(w, http.StatusBadRequest)
			return
		}
	}
	img, err := user.OTPKey.Image(size, size)
	if err != nil {
		serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.WriteHeader(http.StatusOK)
	err = jpeg.Encode(w, img, nil)
	if err != nil {
		log.Error("encode otp qr code: %w", err)
	}
}

// POST /user/2fa/otp/reset
func (h *Handler) resetOTP(w http.ResponseWriter, r *http.Request) {
	userID := h.AuthService.AuthenticatedUserID(r.Context())
	type request struct {
		Password string `form:"password" validate:"required"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "resetOTP", nil)
	if !ok {
		return
	}

	tmplData := h.newTemplateData(r)
	err := h.AuthService.DisableOTP(r.Context(), userID, body.Password)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
			tmplData.FieldErrors["Password"] = services.MustTranslate(lang, "wrongPassword")
			h.Renderer.render(w, r, http.StatusUnprocessableEntity, "resetOTP", tmplData)
		} else {
			serverError(w, err)
		}
		return
	}
	err = h.AuthService.RemoveRemember2FACookie(r.Context(), userID, w, r)
	if err != nil {
		serverError(w, err)
		return
	}
	http.Redirect(w, r, "/user/2fa/otp/activate", http.StatusSeeOther)
}

// GET /user/2fa/recovery
func (h *Handler) recoveryCodesPage(w http.ResponseWriter, r *http.Request) {
	h.storeRedirect(r, "recoveryCodes")
	userID := h.AuthService.AuthenticatedUserID(r.Context())
	has, err := h.AuthService.HasRecoveryCodes(r.Context(), userID)
	if err != nil {
		serverError(w, err)
		return
	}
	if has {
		http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
		return
	}
	codes, err := h.AuthService.GenerateRecoveryCodes(r.Context(), userID)
	if err != nil {
		serverError(w, err)
		return
	}
	data := h.newTemplateData(r)
	type formData struct {
		RecoveryCodes string
	}
	data.Form = formData{
		RecoveryCodes: strings.Join(codes, "\n"),
	}
	h.Renderer.render(w, r, http.StatusOK, "recoveryCodes", data)
}

// POST /user/2fa/recovery
func (h *Handler) recoveryCodes(w http.ResponseWriter, r *http.Request) {
	if h.SessionManager.PopBool(r.Context(), "recoveryCodesDownloaded") {
		h.redirect(w, r, "recoveryCodes")
		return
	}
	type request struct {
		RecoveryCodes string `form:"recoveryCodes" validate:"required"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "recoveryCodes", nil)
	if !ok {
		return
	}
	h.SessionManager.Put(r.Context(), "recoveryCodesDownloaded", true)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=h-id_recovery-codes.txt")
	_, err := w.Write([]byte(strings.TrimSpace(body.RecoveryCodes)))
	if err != nil {
		serverError(w, err)
	}
}

// POST /user/2fa/recovery/reset
func (h *Handler) resetRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Password string `form:"password" validate:"required"`
	}
	body, ok := decodeAndValidateBody[request](h, w, r, "resetRecoveryCodes", nil)
	if !ok {
		return
	}

	tmplData := h.newTemplateData(r)
	err := h.AuthService.DeleteRecoveryCodes(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()), body.Password)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
			tmplData.FieldErrors["Password"] = services.MustTranslate(lang, "wrongPassword")
			h.Renderer.render(w, r, http.StatusUnprocessableEntity, "resetRecoveryCodes", tmplData)
		} else {
			serverError(w, err)
		}
		return
	}
	http.Redirect(w, r, "/user/2fa/recovery", http.StatusSeeOther)
}

// GET /user/changeEmail
func (h *Handler) changeEmailPage(w http.ResponseWriter, r *http.Request) {
	if config.HCaptchaSiteKey() != "" {
		w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
	}
	h.Renderer.render(w, r, http.StatusOK, "changeEmail", h.newTemplateData(r))
}

// POST /user/changeEmail
func (h *Handler) changeEmail(w http.ResponseWriter, r *http.Request) {
	user, err := h.UserService.Find(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()))
	if err != nil {
		serverError(w, err)
		return
	}

	type request struct {
		NewEmail string `form:"email" validate:"required,email"`
		Password string `form:"password" validate:"required"`
	}
	body, ok := decodeAndValidateBodyWithCaptcha[request](h, w, r, "changeEmail", nil)
	if !ok {
		return
	}

	if config.HCaptchaSiteKey() != "" {
		w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
	}

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	tmplData := h.newTemplateData(r)
	tmplData.Form = body
	if body.NewEmail == user.Email {
		tmplData.FieldErrors["NewEmail"] = services.MustTranslate(lang, "newEmailSameAsOld")
		h.Renderer.render(w, r, http.StatusUnprocessableEntity, "changeEmail", tmplData)
		return
	}

	err = h.AuthService.VerifyPasswordByID(r.Context(), user.ID, body.Password)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			tmplData.FieldErrors["Password"] = services.MustTranslate(lang, "wrongPassword")
			h.Renderer.render(w, r, http.StatusUnprocessableEntity, "changeEmail", tmplData)
		} else {
			serverError(w, err)
		}
		return
	}

	_, err = h.UserService.FindByEmail(r.Context(), body.NewEmail)
	if err == nil {
		tmplData.FieldErrors["NewEmail"] = services.MustTranslate(lang, "emailAlreadyInUse")
		h.Renderer.render(w, r, http.StatusUnprocessableEntity, "changeEmail", tmplData)
		return
	}
	if !errors.Is(err, repos.ErrNoRecord) {
		serverError(w, err)
		return
	}

	err = h.UserService.RequestChangeEmail(r.Context(), lang, user, body.NewEmail)
	if err != nil {
		serverError(w, err)
		return
	}
	h.SessionManager.Put(r.Context(), "profilePageSuccess", "emailChangeRequested")
	http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
}

// GET /user/updateEmail
func (h *Handler) updateEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		clientError(w, http.StatusBadRequest)
		return
	}
	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	email, err := h.UserService.ChangeEmail(r.Context(), lang, token)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			h.SessionManager.Put(r.Context(), "profilePageError", "emailChangeFailure")
			http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
		} else if errors.Is(err, repos.ErrExists) {
			h.SessionManager.Put(r.Context(), "profilePageError", "emailChangeFailureExists")
			http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
		} else {
			serverError(w, err)
		}
		return
	}
	user, err := h.UserService.FindByEmail(r.Context(), email)
	if err != nil {
		serverError(w, err)
		return
	}
	if user.ID == h.AuthService.AuthenticatedUserID(r.Context()) {
		h.SessionManager.Put(r.Context(), "profilePageSuccess", "emailChangeSuccess")
		http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
		return
	}
	w.Write([]byte("Success"))
}

// GET /user/profile
func (h *Handler) userProfile(w http.ResponseWriter, r *http.Request) {
	user, err := h.UserService.Find(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()))
	if err != nil {
		serverError(w, err)
		return
	}
	type profileData struct {
		ID      ulid.ULID
		Name    string
		Email   string
		Success string
		Error   string
	}
	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))

	success := h.SessionManager.PopString(r.Context(), "profilePageSuccess")
	success, err = services.Translate(lang, success)
	if err != nil {
		success = ""
	}

	error := h.SessionManager.PopString(r.Context(), "profilePageError")
	error, err = services.Translate(lang, error)
	if err != nil {
		error = ""
	}

	h.Renderer.render(w, r, http.StatusOK, "profile", h.newTemplateDataWithData(r, profileData{
		ID:      user.ID,
		Name:    user.Name,
		Email:   user.Email,
		Success: success,
		Error:   error,
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
		ID    ulid.ULID
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
	body.Name = strings.TrimSpace(body.Name)

	err = h.UserService.Update(r.Context(), h.AuthService.AuthenticatedUserID(r.Context()), body.Name)
	if err != nil {
		serverError(w, err)
		return
	}

	tmplData.Data = userDTO{
		ID:    user.ID,
		Name:  body.Name,
		Email: user.Email,
	}
	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	if pictureFile, pictureHeader, err := r.FormFile("profile_picture"); err == nil {
		if pictureHeader.Size > 10<<20 { // 10 MB
			tmplData.FieldErrors["ProfilePicture"] = services.MustTranslate(lang, "profilePictureTooLarge")
			h.Renderer.render(w, r, http.StatusUnprocessableEntity, "profile", tmplData)
			return
		}

		mimeType, _, err := mime.ParseMediaType(pictureHeader.Header.Get("Content-Type"))
		if err != nil || (mimeType != "image/jpeg" && mimeType != "image/png" && mimeType != "image/gif") {
			tmplData.FieldErrors["ProfilePicture"] = services.MustTranslate(lang, "profilePictureWrongFormat")
			h.Renderer.render(w, r, http.StatusUnprocessableEntity, "profile", tmplData)
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

	userID, err := ulid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}

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
