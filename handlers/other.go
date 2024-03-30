package handlers

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/juho05/h-id/services"
)

func (h *Handler) confirm(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	name := query.Get("name")
	requirePassword, err := strconv.ParseBool(query.Get("requirePassword"))
	if err != nil && query.Get("requirePassword") != "" {
		clientError(w, http.StatusBadRequest)
		return
	}
	t := query.Get("type")
	if t != "delete" {
		clientError(w, http.StatusBadRequest)
		return
	}
	uri, err := url.Parse(query.Get("url"))
	if err != nil {
		clientError(w, http.StatusBadRequest)
		return
	}
	redirectURI := uri.Path
	type data struct {
		RequirePassword bool
	}
	type form struct {
		RedirectURL       string
		Name              string
		ConfirmationToken string
	}

	token := services.GenerateToken(32)
	h.SessionManager.Put(r.Context(), "confirm:"+token, redirectURI)

	tmplData := h.newTemplateDataWithData(r, data{
		RequirePassword: requirePassword,
	})
	tmplData.Form = form{
		RedirectURL:       redirectURI,
		Name:              name,
		ConfirmationToken: token,
	}

	h.Renderer.render(w, r, http.StatusOK, "confirmDelete", tmplData)
}
