package services

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/smtp"
	"path/filepath"
	"strings"

	"github.com/juho05/h-id/config"
	"github.com/juho05/log"
)

type EmailService interface {
	SendEmail(address, subject, messageName string, data EmailTemplateData) error
}

type emailService struct {
	auth      smtp.Auth
	templates map[string]*template.Template
}

type EmailTemplateData struct {
	Name    string
	Code    string
	BaseURL string
	Lang    string
	Email   string
}

func NewEmailTemplateData(name, lang string) EmailTemplateData {
	return EmailTemplateData{
		Name:    name,
		Lang:    lang,
		BaseURL: config.BaseURL(),
	}
}

func NewEmailService(emailFS fs.FS) EmailService {
	emailAuth := smtp.PlainAuth("", config.EmailUsername(), config.EmailPassword(), strings.Split(config.EmailHost(), ":")[0])
	e := &emailService{
		auth:      emailAuth,
		templates: make(map[string]*template.Template),
	}
	err := e.loadTemplates(emailFS)
	if err != nil {
		log.Errorf("Failed to load email templates: %s", err)
	}
	return e
}

func (e *emailService) loadTemplates(emailFS fs.FS) error {
	messages, err := fs.Glob(emailFS, "messages/*.tmpl.html")
	if err != nil {
		return fmt.Errorf("find email templates: %w", err)
	}

	for _, msg := range messages {
		name := strings.TrimSuffix(filepath.Base(msg), ".tmpl.html")

		t, err := template.New(name).Funcs(template.FuncMap{
			"translate": Translate,
		}).ParseFS(emailFS, "base.tmpl.html")
		if err != nil {
			return fmt.Errorf("email: parse base.tmpl.html: %w", err)
		}

		t, err = t.ParseFS(emailFS, msg)
		if err != nil {
			return fmt.Errorf("parse %s: %w", msg, err)
		}

		e.templates[name] = t
	}

	return nil
}

func (e *emailService) SendEmail(address, subject, messageName string, data EmailTemplateData) error {
	if data.Email == "" {
		data.Email = address
	}
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"

	subject = "Subject: " + subject + "\n"
	from := "From: H-ID <" + config.EmailUsername() + ">\n"
	to := "To: " + data.Name + " <" + address + ">\n"

	t, ok := e.templates[messageName]
	if !ok {
		return fmt.Errorf("email template '%s' does not exist", messageName)
	}
	buffer := bytes.Buffer{}
	err := t.ExecuteTemplate(&buffer, "base", data)
	if err != nil {
		return fmt.Errorf("execute email template '%s': %w", messageName, err)
	}

	msg := []byte(subject + from + to + mime + "\n" + buffer.String())
	err = smtp.SendMail(config.EmailHost(), e.auth, config.EmailUsername(), []string{address}, msg)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	return nil
}
