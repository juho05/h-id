package handlers

import (
	"io/fs"
	"mime"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"

	"github.com/juho05/h-id/services"
)

type Handler struct {
	Router         chi.Router
	Renderer       Renderer
	AuthService    services.AuthService
	UserService    services.UserService
	ClientService  services.ClientService
	SessionManager *scs.SessionManager
	EmailService   services.EmailService
	StaticFS       fs.FS
}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Router.ServeHTTP(w, r)
}

func init() {
	mime.AddExtensionType(".js", "text/javascript")
	mime.AddExtensionType(".css", "text/css")
}
