package services

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/smtp"
	"path/filepath"
	"strings"

	"github.com/Bananenpro/h-id/config"
)

type EmailService interface {
	SendEmail(address, subject, messageName string, data emailTemplateData) error
}

type emailService struct {
	auth      smtp.Auth
	templates map[string]*template.Template
}

type emailTemplateData struct {
	Name    string
	Code    string
	BaseURL string
}

func newEmailTemplateData(name string) emailTemplateData {
	return emailTemplateData{
		Name:    name,
		BaseURL: config.BaseURL(),
	}
}

func NewEmailService(emailFS fs.FS) EmailService {
	emailAuth := smtp.PlainAuth("", config.EmailUsername(), config.EmailPassword(), strings.Split(config.EmailHost(), ":")[0])
	e := &emailService{
		auth:      emailAuth,
		templates: make(map[string]*template.Template),
	}
	e.loadTemplates(emailFS)
	return e
}

func (e *emailService) loadTemplates(emailFS fs.FS) error {
	messages, err := fs.Glob(emailFS, "messages/*.tmpl.html")
	if err != nil {
		return fmt.Errorf("find email templates: %w", err)
	}

	for _, msg := range messages {
		name := strings.TrimSuffix(filepath.Base(msg), ".tmpl.html")

		t, err := template.New(name).ParseFS(emailFS, "base.tmpl.html")
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

func (e *emailService) SendEmail(address, subject, messageName string, data emailTemplateData) error {
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"

	subject = "Subject: " + subject + "\n"

	t, ok := e.templates[messageName]
	if !ok {
		return fmt.Errorf("email template '%s' does not exist", messageName)
	}
	buffer := bytes.Buffer{}
	err := t.ExecuteTemplate(&buffer, "base", data)
	if err != nil {
		return fmt.Errorf("execute email template '%s': %w", messageName, err)
	}

	msg := []byte(subject + mime + "\n" + buffer.String())
	err = smtp.SendMail(config.EmailHost(), e.auth, config.EmailUsername(), []string{address}, msg)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	return nil
}
