package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Bananenpro/h-id/repos"
)

func (h *Handler) userRoutes(r chi.Router) {
	r.Post("/signup", h.userSignUp)
}

// POST /user/signup
func (h *Handler) userSignUp(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name     string `json:"name" validate:"required,notblank,min=3,max=32"`
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=6,maxsize=72"`
	}
	body, err := decodeBody[request](r)
	if err != nil {
		badRequest(w)
		return
	}

	invalid := findInvalidFields(body)
	if len(invalid) > 0 {
		invalidFields(w, invalid)
		return
	}

	user, err := h.UserService.Create(r.Context(), body.Name, body.Email, body.Password)
	if err != nil {
		if errors.Is(err, repos.ErrDuplicateEmail) {
			respondError(w, ErrUserExists, http.StatusConflict, nil)
		} else {
			serverError(w, err)
		}
		return
	}

	type response struct {
		ID             string    `json:"id"`
		Name           string    `json:"name"`
		Email          string    `json:"email"`
		EmailConfirmed bool      `json:"emailConfirmed"`
		Created        time.Time `json:"created"`
	}
	respond(w, http.StatusCreated, response{
		ID:             user.ID,
		Name:           user.Name,
		Email:          user.Email,
		EmailConfirmed: user.EmailConfirmed,
		Created:        user.Created,
	})
}
