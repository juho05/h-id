package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/go-playground/form/v4"
	"github.com/go-playground/locales/de"
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	"github.com/go-playground/validator/v10/non-standard/validators"
	entrans "github.com/go-playground/validator/v10/translations/en"
	"github.com/juho05/log"

	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/services"
)

var (
	validate *validator.Validate
	enTrans  ut.Translator
	deTrans  ut.Translator
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
	de := de.New()
	uni := ut.New(en, en, de)
	enTrans, _ = uni.GetTranslator("en")
	deTrans, _ = uni.GetTranslator("de")
	entrans.RegisterDefaultTranslations(validate, enTrans)
	services.RegisterDETranslations(validate, deTrans)
	err := validate.RegisterTranslation("notblank", enTrans, registrationFunc("notblank", "{0} must not be blank"), translateFunc)
	if err != nil {
		log.Fatal(err)
	}
	err = validate.RegisterTranslation("maxsize", enTrans, registrationFunc("maxsize", "{0} must not exceed {1} bytes"), translateFunc)
	if err != nil {
		log.Fatal(err)
	}
	err = validate.RegisterTranslation("notblank", deTrans, registrationFunc("notblank", "{0} darf nicht leer sein"), translateFunc)
	if err != nil {
		log.Fatal(err)
	}
	err = validate.RegisterTranslation("maxsize", deTrans, registrationFunc("maxsize", "{0} darf nicht größer als {1} bytes sein"), translateFunc)
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

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	invalid := findInvalidFields(lang, data)
	if len(invalid) > 0 {
		if templateData == nil {
			d := handler.newTemplateData(r)
			templateData = &d
		}
		templateData.Form = data
		templateData.FieldErrors = invalid
		handler.Renderer.render(w, r, http.StatusUnprocessableEntity, page, *templateData)
		return data, false
	}

	return data, true
}

func decodeAndValidateBodyWithCaptcha[T any](handler *Handler, w http.ResponseWriter, r *http.Request, page string, templateData *templateData) (data T, ok bool) {
	data, err := decodeBody[T](r)
	if err != nil {
		badRequest(w)
		return data, false
	}

	lang := services.GetLanguageFromAcceptLanguageHeader(strings.Join(r.Header["Accept-Language"], ","))
	invalid := findInvalidFields(lang, data)

	if config.HCaptchaSiteKey() != "" {
		hcaptchaResponse := r.PostForm.Get("h-captcha-response")

		values := url.Values{}
		values.Set("response", hcaptchaResponse)
		values.Set("secret", config.HCaptchaSecret())
		values.Set("sitekey", config.HCaptchaSiteKey())
		resp, err := http.PostForm("https://hcaptcha.com/siteverify", values)
		if err != nil {
			serverError(w, fmt.Errorf("verify captcha response: %w", err))
			return
		}
		defer resp.Body.Close()
		type response struct {
			Success    bool     `json:"success"`
			ErrorCodes []string `json:"error-codes"`
		}
		var res response
		err = json.NewDecoder(resp.Body).Decode(&res)
		if err != nil {
			serverError(w, fmt.Errorf("decode captcha siteverify response: %w", err))
			return
		}
		if !res.Success {
			if invalid == nil {
				invalid = make(map[string]string)
			}
			invalid["Captcha"] = "Please solve the CAPTCHA challenge"
			for _, e := range res.ErrorCodes {
				if e != "missing-input-response" && e != "invalid-input-response" && e != "invalid-or-already-seen-response" {
					log.Error(fmt.Sprintf("captcha siteverify: %s", e))
				}
			}
		}
		w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
	}

	if len(invalid) > 0 {
		if templateData == nil {
			d := handler.newTemplateData(r)
			templateData = &d
		}
		templateData.Form = data
		templateData.FieldErrors = invalid
		handler.Renderer.render(w, r, http.StatusUnprocessableEntity, page, *templateData)
		return data, false
	}

	return data, true
}

func decodeBody[T any](r *http.Request) (T, error) {
	var obj T

	var err error
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil && mediaType == "multipart/form-data" {
		err = r.ParseMultipartForm(32 << 20) // 32 MB buffer
	} else {
		err = r.ParseForm()
	}
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

func findInvalidFields(lang string, obj any) map[string]string {
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
			if lang == "de" {
				fields[name] = e.Translate(deTrans)
			} else {
				fields[name] = e.Translate(enTrans)
			}
		}
		return fields
	}
	return nil
}

func (h *Handler) newPage(name string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Renderer.render(w, r, http.StatusOK, name, h.newTemplateData(r))
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

func noCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func matchETagHeader(current, header string, weak bool) bool {
	for _, e := range strings.Split(header, ",") {
		e = strings.TrimSpace(header)
		if e == "" {
			continue
		}
		if !strings.HasPrefix(header, "W/") && weak {
			continue
		}
		e = strings.TrimPrefix(e, "W/")
		e = strings.Trim(e, "\"")
		if e == current || e == "*" {
			return true
		}
	}
	return false
}

type URL struct {
	URL *url.URL
}

func (u URL) MarshalText() ([]byte, error) {
	return []byte(u.URL.String()), nil
}

func (u *URL) UnmarshalText(text []byte) error {
	uri, err := url.Parse(string(text))
	if err != nil {
		return errors.New("invalid URL")
	}
	u.URL = uri
	return nil
}

func stringsToStdURLs(urls []string) ([]*url.URL, error) {
	std := make([]*url.URL, len(urls))
	var err error
	for i, u := range urls {
		std[i], err = url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("strings to std urls: %w", err)
		}
	}
	return std, nil
}

func urlsToStdURLs(urls []URL) []*url.URL {
	std := make([]*url.URL, len(urls))
	for i, u := range urls {
		std[i] = u.URL
	}
	return std
}

func urlsToStrings(urls []*url.URL) []string {
	strings := make([]string, len(urls))
	for i, u := range urls {
		strings[i] = u.String()
	}
	return strings
}
