package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"

	"github.com/juho05/h-id/repos"
)

func (h *Handler) appRoutes(r chi.Router) {
	r.Use(h.auth)
	r.Get("/create", h.newPage("createApp"))
	r.Post("/create", h.appCreate)
	r.Get("/list", h.appList)
	r.Get("/{id}", h.appGet)
	r.Put("/{id}", h.appUpdate)
}

// POST /app/create
func (h *Handler) appCreate(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name         string `form:"name" validate:"required,notblank,min=3,max=32"`
		Description  string `form:"description" validate:"max=512"`
		Website      URL    `form:"website" validate:"required"`
		RedirectURIs []URL  `form:"redirectURIs" validate:"required,min=1,dive,required"`
	}

	body, ok := decodeAndValidateBody[request](h, w, r, "createApp", nil)
	if !ok {
		return
	}

	userID := h.AuthService.AuthenticatedUserID(r.Context())
	client, secret, err := h.ClientService.Create(r.Context(), userID, body.Name, body.Description, body.Website.URL, urlsToStdURLs(body.RedirectURIs))
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

	sbuilder := strings.Builder{}
	for i, c := range clients {
		if i > 0 {
			sbuilder.WriteString(", ")
		}
		sbuilder.WriteString(c.Name)
		sbuilder.WriteString("(")
		sbuilder.WriteString(c.ID.String())
		sbuilder.WriteString(")")
	}
	w.Write([]byte(sbuilder.String()))
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

	response := client.Name
	for _, u := range client.RedirectURIs {
		response += "\n" + u.String()
	}

	if secret := h.SessionManager.PopString(r.Context(), "clientSecret:"+client.ID.String()); secret != "" {
		response += ": " + secret
	}

	w.Write([]byte(response))
}

// PUT /app/{id}
func (h *Handler) appUpdate(w http.ResponseWriter, r *http.Request) {
	clientError(w, http.StatusNotImplemented)
}