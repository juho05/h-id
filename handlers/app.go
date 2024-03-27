package handlers

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"

	"github.com/juho05/h-id/repos"
)

func (h *Handler) appRoutes(r chi.Router) {
	r.Get("/create", h.newPage("createApp"))
	r.Post("/create", h.appCreate)
	r.Get("/list", h.appList)
	r.Get("/{id}", h.appGet)
	r.Post("/{id}/update", h.appUpdate)
	r.Post("/{id}/delete", h.appDelete)
}

// POST /app/create
func (h *Handler) appCreate(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name         string   `form:"name" validate:"required,notblank,min=3,max=32"`
		Description  string   `form:"description" validate:"max=512"`
		Website      string   `form:"website" validate:"required,http_url"`
		RedirectURIs []string `form:"redirectURIs" validate:"required,min=1,dive,required,http_url"`
	}

	body, ok := decodeAndValidateBody[request](h, w, r, "createApp", nil)
	if !ok {
		return
	}

	website, err := url.Parse(body.Website)
	if err != nil {
		serverError(w, err)
		return
	}
	redirectURLs, err := stringsToStdURLs(body.RedirectURIs)
	if err != nil {
		serverError(w, err)
		return
	}

	userID := h.AuthService.AuthenticatedUserID(r.Context())
	client, secret, err := h.ClientService.Create(r.Context(), userID, body.Name, body.Description, website, redirectURLs)
	if err != nil {
		serverError(w, err)
		return
	}

	h.SessionManager.Put(r.Context(), "clientSecret:"+client.ID.String(), secret)
	http.Redirect(w, r, "/app/"+client.ID.String(), http.StatusSeeOther)
}

// GET /app/list
func (h *Handler) appList(w http.ResponseWriter, r *http.Request) {
	userID := h.AuthService.AuthenticatedUserID(r.Context())
	clients, err := h.ClientService.FindByUser(r.Context(), userID)
	if err != nil {
		serverError(w, err)
		return
	}
	type app struct {
		ID   string
		Name string
	}
	type data struct {
		Apps []app
	}
	apps := make([]app, len(clients))
	for i, c := range clients {
		apps[i] = app{
			ID:   c.ID.String(),
			Name: c.Name,
		}
	}
	h.Renderer.render(w, r, http.StatusOK, "listApps", h.newTemplateDataWithData(r, data{
		Apps: apps,
	}))
}

// GET /app/{id}
func (h *Handler) appGet(w http.ResponseWriter, r *http.Request) {
	id, err := ulid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}
	userID := h.AuthService.AuthenticatedUserID(r.Context())
	client, err := h.ClientService.FindByUserAndID(r.Context(), userID, id)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else {
			serverError(w, err)
		}
		return
	}

	if secret := h.SessionManager.PopString(r.Context(), "clientSecret:"+id.String()); secret != "" {
		type data struct {
			ID     string
			Secret string
			Name   string
		}
		h.Renderer.render(w, r, http.StatusOK, "appCreated", h.newTemplateDataWithData(r, data{
			ID:     id.String(),
			Secret: secret,
			Name:   client.Name,
		}))
		return
	}

	type data struct {
		ID string
	}
	tmplData := h.newTemplateDataWithData(r, data{
		ID: id.String(),
	})
	type form struct {
		Name         string
		Description  string
		Website      string
		RedirectURIs []string
		EncodedName  string
	}
	tmplData.Form = form{
		Name:         client.Name,
		Description:  client.Description,
		Website:      client.Website.String(),
		RedirectURIs: urlsToStrings(client.RedirectURIs),
		EncodedName:  url.QueryEscape(client.Name),
	}
	h.Renderer.render(w, r, http.StatusOK, "app", tmplData)
}

// POST /app/{id}/update
func (h *Handler) appUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := ulid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}

	type request struct {
		Name         string   `form:"name" validate:"required,notblank,min=3,max=32"`
		Description  string   `form:"description" validate:"max=512"`
		Website      string   `form:"website" validate:"required,http_url"`
		RedirectURIs []string `form:"redirectURIs" validate:"required,min=1,dive,required,http_url"`
		EncodedName  string   `form:"encodedName" validate:"required"`
	}

	tmplData := h.newTemplateDataWithData(r, struct{ ID string }{ID: id.String()})
	body, ok := decodeAndValidateBody[request](h, w, r, "app", &tmplData)
	if !ok {
		return
	}

	website, err := url.Parse(body.Website)
	if err != nil {
		serverError(w, err)
		return
	}
	redirectURLs, err := stringsToStdURLs(body.RedirectURIs)
	if err != nil {
		serverError(w, err)
		return
	}

	userID := h.AuthService.AuthenticatedUserID(r.Context())
	err = h.ClientService.Update(r.Context(), userID, id, body.Name, body.Description, website, redirectURLs)
	if err != nil {
		serverError(w, err)
		return
	}

	http.Redirect(w, r, "/app/"+id.String(), http.StatusSeeOther)
}

// POST /app/{id}/delete
func (h *Handler) appDelete(w http.ResponseWriter, r *http.Request) {
	id, err := ulid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}
	userID := h.AuthService.AuthenticatedUserID(r.Context())
	err = h.ClientService.Delete(r.Context(), userID, id)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			clientError(w, http.StatusNotFound)
		} else {
			serverError(w, err)
		}
		return
	}
	http.Redirect(w, r, "/app/list", http.StatusSeeOther)
}
