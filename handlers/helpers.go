package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/Bananenpro/log"
	"github.com/go-playground/form/v4"
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	"github.com/go-playground/validator/v10/non-standard/validators"
	entrans "github.com/go-playground/validator/v10/translations/en"

	"github.com/Bananenpro/h-id/repos"
)

var (
	validate *validator.Validate
	enTrans  ut.Translator
)

func maxSize(fl validator.FieldLevel) bool {
	field := fl.Field()
	if field.Kind() != reflect.String {
		panic("maxsize only supports strings")
	}
	param, err := strconv.Atoi(fl.Param())
	if err != nil {
		panic("maxsize parameter must be an integer")
	}
	return len(field.String()) <= param
}

func init() {
	validate = validator.New()
	validate.RegisterValidation("notblank", validators.NotBlank)
	validate.RegisterValidation("maxsize", maxSize)

	en := en.New()
	uni := ut.New(en, en)
	enTrans, _ = uni.GetTranslator("en")
	entrans.RegisterDefaultTranslations(validate, enTrans)
	err := validate.RegisterTranslation("notblank", enTrans, registrationFunc("notblank", "{0} must not be blank"), translateFunc)
	if err != nil {
		log.Fatal(err)
	}
	err = validate.RegisterTranslation("maxsize", enTrans, registrationFunc("maxsize", "{0} must not exceed {1} bytes"), translateFunc)
	if err != nil {
		log.Fatal(err)
	}
}

func registrationFunc(tag string, translation string) validator.RegisterTranslationsFunc {
	return func(ut ut.Translator) (err error) {
		if err = ut.Add(tag, translation, false); err != nil {
			return
		}

		return
	}
}

func translateFunc(ut ut.Translator, fe validator.FieldError) string {
	t, err := ut.T(fe.Tag(), fe.Field(), fe.Param())
	if err != nil {
		log.Warnf("Error translating FieldError: %#v", fe)
		return fe.(error).Error()
	}

	return t
}

var formDecoder = form.NewDecoder()

func decodeAndValidateBody[T any](handler *Handler, w http.ResponseWriter, r *http.Request, page string, templateData *templateData) (data T, ok bool) {
	data, err := decodeBody[T](r)
	if err != nil {
		badRequest(w)
		return data, false
	}

	invalid := findInvalidFields(data)
	if len(invalid) > 0 {
		if templateData == nil {
			d := handler.newTemplateData(r)
			templateData = &d
		}
		templateData.Form = data
		templateData.FieldErrors = invalid
		handler.Renderer.render(w, http.StatusUnprocessableEntity, page, *templateData)
		return data, false
	}

	return data, true
}

func decodeBody[T any](r *http.Request) (T, error) {
	var obj T

	err := r.ParseForm()
	if err != nil {
		return obj, fmt.Errorf("decode form body: %w", err)
	}

	err = formDecoder.Decode(&obj, r.PostForm)
	r.Body.Close()
	var invalidDecoderError *form.InvalidDecoderError
	if errors.As(err, &invalidDecoderError) {
		panic(err)
	}
	return obj, err
}

func findInvalidFields(obj any) map[string]string {
	err := validate.Struct(obj)
	if e, ok := err.(*validator.InvalidValidationError); ok {
		panic(e)
	}

	vErrs, ok := err.(validator.ValidationErrors)
	if ok && len(vErrs) > 0 {
		fields := make(map[string]string, len(vErrs))
		for _, e := range vErrs {
			name := e.StructField()
			name = strings.ReplaceAll(name, "[", "")
			name = strings.ReplaceAll(name, "]", "")
			fields[name] = e.Translate(enTrans)
		}
		return fields
	}
	return nil
}

func (h *Handler) newPage(name string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Renderer.render(w, http.StatusOK, name, h.newTemplateData(r))
	}
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

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondJSONError(w http.ResponseWriter, err error, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	type response struct {
		Error string `json:"error"`
	}
	res := response{
		Error: err.Error(),
	}
	json.NewEncoder(w).Encode(res)
}

func (h *Handler) authUser(w http.ResponseWriter, r *http.Request) (user *repos.UserModel, ok bool) {
	userID := h.AuthService.AuthenticatedUserID(r.Context())

	user, err := h.UserService.Find(r.Context(), userID)
	if err != nil {
		h.SessionManager.Destroy(r.Context())
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return nil, false
	}

	return user, true
}
