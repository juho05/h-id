package handlers

import (
	"net/http"
	"net/url"
)

func (h *Handler) confirm(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	name := query.Get("name")
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
		RedirectURL string
		Name        string
	}
	h.Renderer.render(w, r, http.StatusOK, "confirmDelete", h.newTemplateDataWithData(r, data{
		RedirectURL: redirectURI,
		Name:        name,
	}))
}
