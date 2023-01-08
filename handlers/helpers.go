package handlers

import (
	"encoding/json"
	"net/http"
	"reflect"
	"runtime/debug"
	"strings"

	"github.com/Bananenpro/log"
	"github.com/go-playground/validator/v10"
	"github.com/go-playground/validator/v10/non-standard/validators"
)

var validate *validator.Validate

func maxSize(fl validator.FieldLevel) bool {
	field := fl.Field()
	if field.Kind() != reflect.String {
		panic("maxsize only supports strings")
	}
	return len(field.String()) > 0
}

func init() {
	validate = validator.New()
	validate.RegisterTagNameFunc(func(field reflect.StructField) string {
		name := strings.SplitN(field.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
	validate.RegisterValidation("notblank", validators.NotBlank)
	validate.RegisterValidation("maxsize", maxSize)
}

func decodeBody[T any](r *http.Request) (T, error) {
	var obj T
	err := json.NewDecoder(r.Body).Decode(&obj)
	r.Body.Close()
	return obj, err
}

type invalidField struct {
	Name string `json:"name"`
	Rule string `json:"rule"`
}

func findInvalidFields(obj any) []invalidField {
	err := validate.Struct(obj)
	if e, ok := err.(*validator.InvalidValidationError); ok {
		panic(e)
	}

	vErrs, ok := err.(validator.ValidationErrors)
	if ok && len(vErrs) > 0 {
		fields := make([]invalidField, len(vErrs))
		for i, e := range vErrs {
			fields[i] = invalidField{
				Name: e.Field(),
				Rule: e.Tag(),
			}
		}
		return fields
	}
	return nil
}

func invalidFields(w http.ResponseWriter, fields []invalidField) {
	type response struct {
		Fields []invalidField `json:"fields"`
	}
	respondError(w, ErrInvalidFields, http.StatusUnprocessableEntity, response{
		Fields: fields,
	})
}

func notFound(w http.ResponseWriter) {
	clientError(w, http.StatusNotFound)
}

func badRequest(w http.ResponseWriter) {
	clientError(w, http.StatusBadRequest)
}

func clientError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func serverError(w http.ResponseWriter, err error) {
	log.Errorf("%s\n%s", err.Error(), debug.Stack())
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func respond(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	type response struct {
		Error bool `json:"error"`
		Body  any  `json:"body,omitempty"`
	}
	res := response{
		Error: false,
		Body:  data,
	}
	json.NewEncoder(w).Encode(res)
}

func respondError(w http.ResponseWriter, err error, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	type response struct {
		Error   bool   `json:"error"`
		ErrorID string `json:"errorID"`
		Body    any    `json:"body,omitempty"`
	}
	res := response{
		Error:   true,
		ErrorID: err.Error(),
		Body:    data,
	}
	json.NewEncoder(w).Encode(res)
}
