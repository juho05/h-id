package handlers

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"

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
	clientIDStr := r.URL.Query().Get("client_id")
	redirectURIStr := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	responseType := r.URL.Query().Get("response_type")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")

	clientID, err := ulid.Parse(clientIDStr)
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}

	redirectURI, err := url.Parse(redirectURIStr)
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}

	if responseType == "" {
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
			q := redirectURI.Query()
			q.Add("error", "unsupported_response_type")
			if state != "" {
				q.Add("state", state)
			}
			redirectURI.RawQuery = q.Encode()
			http.Redirect(w, r, redirectURI.String(), http.StatusSeeOther)
		} else if errors.Is(err, services.ErrInvalidScope) {
			q := redirectURI.Query()
			q.Add("error", "invalid_scope")
			if state != "" {
				q.Add("state", state)
			}
			redirectURI.RawQuery = q.Encode()
			http.Redirect(w, r, redirectURI.String(), http.StatusSeeOther)
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

		q := authRequest.RedirectURI.Query()
		q.Add("code", code)
		if authRequest.State != "" {
			q.Add("state", authRequest.State)
		}
		authRequest.RedirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, authRequest.RedirectURI.String(), http.StatusSeeOther)
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
	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	h.Renderer.render(w, r, http.StatusOK, "oauthConsent", h.newTemplateDataWithData(r, tmplData{
		ClientName:        client.Name,
		ClientDescription: client.Description,
		ClientWebsite:     client.Website.String(),
		Scopes:            h.AuthService.DescribeScopes(lang, authRequest.Scopes),
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

	if data.Choice != "accept" {
		q := req.RedirectURI.Query()
		q.Add("error", "access_denied")
		if req.State != "" {
			q.Add("state", req.State)
		}
		req.RedirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, req.RedirectURI.String(), http.StatusSeeOther)
		return
	}

	code, err := h.AuthService.OAuthConsent(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}

	q := req.RedirectURI.Query()
	q.Add("code", code)
	if req.State != "" {
		q.Add("state", req.State)
	}
	req.RedirectURI.RawQuery = q.Encode()
	http.Redirect(w, r, req.RedirectURI.String(), http.StatusSeeOther)
}

func (h *Handler) oauthToken(w http.ResponseWriter, r *http.Request) {
	noCache(w)

	type request struct {
		GrantType    string `form:"grant_type"`
		Code         string `form:"code"`
		RedirectURI  URL    `form:"redirect_uri"`
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
	clientIDStr, err := url.QueryUnescape(username)
	if err != nil {
		respondJSONError(w, errors.New("invalid_request"), http.StatusBadRequest)
		return
	}
	clientID, err := ulid.Parse(clientIDStr)
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

	access, refresh, id, err := h.AuthService.OAuthGenerateTokens(r.Context(), clientID, clientSecret, data.RedirectURI.URL, data.GrantType, grant)
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

	pubKey := h.AuthService.PublicJWTKey()

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
