package handlers

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/services"
)

func (h *Handler) oauthRoutes(r chi.Router) {
	r.With(h.auth).Get("/auth", h.oauthAuth)
	r.With(h.auth).Get("/consent", h.oauthConsentPage)
	r.With(h.auth).Post("/consent", h.oauthConsent)

	r.Get("/certs", h.oauthCerts)

	r.Post("/token", h.oauthToken)
}

func (h *Handler) oauthAuth(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	responseType := r.URL.Query().Get("response_type")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")

	if clientID == "" || redirectURI == "" || responseType == "" {
		clientError(w, http.StatusBadRequest)
		return
	}

	redirect, err := url.Parse(redirectURI)
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}

	err = h.AuthService.StartOAuthCodeFlow(r.Context(), clientID, redirectURI, responseType, scope, state, nonce)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else if errors.Is(err, services.ErrInvalidRedirectURI) {
			clientError(w, http.StatusBadRequest)
		} else if errors.Is(err, services.ErrUnsupportedResponseType) {
			q := redirect.Query()
			q.Add("error", "unsupported_response_type")
			if state != "" {
				q.Add("state", state)
			}
			redirect.RawQuery = q.Encode()
			http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
		} else if errors.Is(err, services.ErrInvalidScope) {
			q := redirect.Query()
			q.Add("error", "invalid_scope")
			if state != "" {
				q.Add("state", state)
			}
			redirect.RawQuery = q.Encode()
			http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
		} else {
			serverError(w, err)
		}
		return
	}

	http.Redirect(w, r, "/oauth/consent", http.StatusSeeOther)
}

func (h *Handler) oauthConsentPage(w http.ResponseWriter, r *http.Request) {
	authRequest, err := h.AuthService.GetAuthRequest(r.Context())
	if err != nil {
		if errors.Is(err, services.ErrMissingRequiredSessionData) {
			clientError(w, http.StatusBadRequest)
		} else {
			serverError(w, err)
		}
		return
	}
	if !authRequest.NeedsConsent {
		code, err := h.AuthService.OAuthConsent(r.Context())
		if err != nil {
			serverError(w, err)
			return
		}

		redirect, err := url.Parse(authRequest.RedirectURI)
		if err != nil {
			serverError(w, fmt.Errorf("oauth consent page handler: %w", err))
			return
		}

		q := redirect.Query()
		q.Add("code", code)
		if authRequest.State != "" {
			q.Add("state", authRequest.State)
		}
		redirect.RawQuery = q.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
		return
	}

	client, err := h.ClientService.Find(r.Context(), authRequest.ClientID)
	if err != nil {
		serverError(w, err)
		return
	}

	type tmplData struct {
		ClientName        string
		ClientDescription string
		ClientWebsite     string
		Scopes            []string
	}
	h.Renderer.render(w, r, http.StatusOK, "oauthConsent", h.newTemplateDataWithData(r, tmplData{
		ClientName:        client.Name,
		ClientDescription: client.Description,
		ClientWebsite:     client.Website,
		Scopes:            h.AuthService.DescribeScopes(authRequest.Scopes),
	}))
}

func (h *Handler) oauthConsent(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Choice string `form:"choice" validate:"required"`
	}
	data, ok := decodeAndValidateBody[request](h, w, r, "oauthConsent", nil)
	if !ok {
		return
	}

	req, err := h.AuthService.GetAuthRequest(r.Context())
	if err != nil {
		if errors.Is(err, services.ErrMissingRequiredSessionData) {
			clientError(w, http.StatusBadRequest)
		} else {
			serverError(w, err)
		}
		return
	}
	redirect, err := url.Parse(req.RedirectURI)
	if err != nil {
		serverError(w, fmt.Errorf("oauth consent handler: %w", err))
		return
	}

	if data.Choice != "accept" {
		q := redirect.Query()
		q.Add("error", "access_denied")
		if req.State != "" {
			q.Add("state", req.State)
		}
		redirect.RawQuery = q.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
		return
	}

	code, err := h.AuthService.OAuthConsent(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}

	q := redirect.Query()
	q.Add("code", code)
	if req.State != "" {
		q.Add("state", req.State)
	}
	redirect.RawQuery = q.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

func (h *Handler) oauthToken(w http.ResponseWriter, r *http.Request) {
	noCache(w)

	type request struct {
		GrantType    string `form:"grant_type"`
		Code         string `form:"code"`
		RedirectURI  string `form:"redirect_uri"`
		RefreshToken string `form:"refresh_token"`
	}

	data, err := decodeBody[request](r)
	if err != nil {
		respondJSONError(w, errors.New("invalid_request"), http.StatusBadRequest)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"client authentication\"")
		respondJSONError(w, errors.New("invalid_client"), http.StatusUnauthorized)
		return
	}
	clientID, err := url.QueryUnescape(username)
	if err != nil {
		respondJSONError(w, errors.New("invalid_request"), http.StatusBadRequest)
		return
	}
	clientSecret, err := url.QueryUnescape(password)
	if err != nil {
		respondJSONError(w, errors.New("invalid_request"), http.StatusBadRequest)
		return
	}

	var grant string
	switch data.GrantType {
	case "authorization_code":
		grant = data.Code
	case "refresh_token":
		grant = data.RefreshToken
	}

	access, refresh, id, err := h.AuthService.OAuthGenerateTokens(r.Context(), clientID, clientSecret, data.RedirectURI, data.GrantType, grant)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"client authentication\"")
			respondJSONError(w, errors.New("invalid_client"), http.StatusUnauthorized)
		} else if errors.Is(err, services.ErrUnsupportedGrantType) {
			respondJSONError(w, errors.New("unsupported_grant_type"), http.StatusBadRequest)
		} else if errors.Is(err, services.ErrInvalidGrant) || errors.Is(err, services.ErrReusedToken) {
			respondJSONError(w, errors.New("invalid_grant"), http.StatusBadRequest)
		} else if errors.Is(err, services.ErrInvalidRedirectURI) {
			respondJSONError(w, errors.New("invalid_request"), http.StatusBadRequest)
		} else {
			serverError(w, err)
		}
		return
	}

	type response struct {
		TokenType    string `json:"token_type"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token,omitempty"`
	}
	respondJSON(w, http.StatusOK, response{
		TokenType:    "bearer",
		AccessToken:  access,
		RefreshToken: refresh,
		IDToken:      id,
	})
}

func (h *Handler) oauthCerts(w http.ResponseWriter, r *http.Request) {
	type key struct {
		Type      string `json:"kty"`
		Use       string `json:"use"`
		Algorithm string `json:"alg"`
		ID        string `json:"kid"`
		N         string `json:"n"`
		E         string `json:"e"`
	}
	type response struct {
		Keys []key `json:"keys"`
	}

	pubKey := config.JWTPublicKey()

	n := base64.URLEncoding.EncodeToString(pubKey.N.Bytes())
	e := base64.URLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())

	idHash := sha1.Sum(x509.MarshalPKCS1PublicKey(pubKey))
	kid := base64.URLEncoding.EncodeToString(idHash[:])

	resp := response{
		Keys: []key{
			{
				Type:      "RSA",
				Use:       "sig",
				Algorithm: "RS256",
				ID:        kid,
				N:         n,
				E:         e,
			},
		},
	}
	respondJSON(w, http.StatusOK, resp)
}
