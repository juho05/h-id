package handlers

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/justinas/nosurf"
	"github.com/oklog/ulid/v2"

	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/services"
)

type templateData struct {
	Form        any
	Data        any
	Lang        string
	InviteOnly  bool
	FieldErrors map[string]string
	Errors      []string
	CSRFToken   string
	SiteKey     string
	UserID      string
}

func (h *Handler) newTemplateData(r *http.Request) templateData {
	userID := h.AuthService.AuthenticatedUserID(r.Context())
	var userIDStr string
	if userID != (ulid.ULID{}) {
		userIDStr = userID.String()
	}
	return templateData{
		FieldErrors: make(map[string]string),
		CSRFToken:   nosurf.Token(r),
		SiteKey:     config.HCaptchaSiteKey(),
		UserID:      userIDStr,
		InviteOnly:  config.InviteOnly(),
	}
}

func (h *Handler) newTemplateDataWithData(r *http.Request, data any) templateData {
	tmplData := h.newTemplateData(r)
	tmplData.Data = data
	return tmplData
}

type Renderer interface {
	render(w http.ResponseWriter, r *http.Request, status int, page string, data templateData)
}

type renderer struct {
	templates map[string]*template.Template
}

func NewRenderer(htmlFS fs.FS) (Renderer, error) {
	renderer := &renderer{
		templates: make(map[string]*template.Template),
	}
	err := renderer.loadTemplates(htmlFS)
	if err != nil {
		return nil, err
	}
	return renderer, nil
}

func (r *renderer) render(w http.ResponseWriter, req *http.Request, status int, page string, data templateData) {
	t, ok := r.templates[page]
	if !ok {
		serverError(w, fmt.Errorf("template %s does not exist", page))
		return
	}

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(req.Header["Accept-Language"], ","))
	data.Lang = lang
	buf := &bytes.Buffer{}
	err := t.ExecuteTemplate(buf, "base", data)
	if err != nil {
		serverError(w, err)
		return
	}

	w.WriteHeader(status)
	buf.WriteTo(w)
}

func (r *renderer) loadTemplates(htmlFS fs.FS) error {
	pages, err := fs.Glob(htmlFS, "pages/*.tmpl.html")
	if err != nil {
		return fmt.Errorf("find html pages: %w", err)
	}

	for _, page := range pages {
		name := strings.TrimSuffix(filepath.Base(page), ".tmpl.html")

		t, err := template.New(name).Funcs(template.FuncMap{
			"translate": services.Translate,
		}).ParseFS(htmlFS, "base.tmpl.html")
		if err != nil {
			return fmt.Errorf("parse base.tmpl.html: %w", err)
		}

		if partials, err := fs.ReadDir(htmlFS, "partials"); err == nil && len(partials) > 0 {
			t, err = t.ParseFS(htmlFS, "partials/*.tmpl.html")
			if err != nil {
				return fmt.Errorf("parse template partials: %w", err)
			}
		}

		t, err = t.ParseFS(htmlFS, page)
		if err != nil {
			return fmt.Errorf("parse %s: %w", page, err)
		}

		r.templates[name] = t
	}

	return nil
}
