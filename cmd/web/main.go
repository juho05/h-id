package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/juho05/log"

	hid "github.com/juho05/h-id"

	"github.com/joho/godotenv"

	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/handlers"
	"github.com/juho05/h-id/repos/sqlite"
	"github.com/juho05/h-id/services"
)

func run() error {
	handler := handlers.NewHandler()

	db, err := sqlite.Connect(config.DBFile())
	if err != nil {
		return fmt.Errorf("Failed to connect to database: %w", err)
	}
	defer db.Close()

	userRepo := db.NewUserRepository()
	tokenRepo := db.NewTokenRepository()
	clientRepo := db.NewClientRepository()
	oauthRepo := db.NewOAuthRepository()
	systemRepo := db.NewSystemRepository()

	handler.SessionManager = scs.New()
	handler.SessionManager.Store = db.NewSessionRepository()
	handler.SessionManager.Lifetime = config.SessionLifetime()
	handler.SessionManager.IdleTimeout = config.SessionIdleTimeout()
	handler.SessionManager.Cookie.Secure = true
	handler.SessionManager.Cookie.Name = "h-id_session"
	handler.SessionManager.Cookie.Domain = config.AuthGatewayDomain()

	emailService := services.NewEmailService(hid.EmailFS)

	handler.EmailService = emailService
	handler.AuthService, err = services.NewAuthService(userRepo, tokenRepo, oauthRepo, clientRepo, systemRepo, handler.SessionManager, emailService)
	if err != nil {
		return fmt.Errorf("new auth service: %w", err)
	}
	handler.UserService = services.NewUserService(userRepo, handler.AuthService, emailService)
	handler.ClientService = services.NewClientService(clientRepo)

	handler.Renderer, err = handlers.NewRenderer(hid.HTMLFS)
	if err != nil {
		return fmt.Errorf("Failed to initialize renderer: %w", err)
	}

	handler.AuthGatewayService, err = services.NewAuthGatewayService()
	if err != nil {
		return fmt.Errorf("Failed to initialize auth gateway service: %w", err)
	}

	handler.StaticFS = hid.StaticFS
	handler.RegisterRoutes()

	cert := config.TLSCert()
	key := config.TLSKey()

	var addr string
	if config.Local() {
		addr = fmt.Sprintf("localhost:%d", config.Port())
	} else {
		addr = fmt.Sprintf("0.0.0.0:%d", config.Port())
	}

	server := http.Server{
		Addr:     addr,
		Handler:  handler,
		ErrorLog: log.NewStdLogger(log.ERROR),
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	closed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		<-sigint
		timeout, cancelTimeout := context.WithTimeout(context.Background(), 5*time.Second)
		log.Info("Shutting down...")
		server.Shutdown(timeout)
		cancelTimeout()
		close(closed)
	}()

	if cert != "" && key != "" {
		log.Infof("Listening on https://%s...", addr)
		err = server.ListenAndServeTLS(cert, key)
	} else {
		log.Infof("Listening on http://%s...", addr)
		err = server.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	if err == nil {
		<-closed
	}
	return err
}

func main() {
	godotenv.Load()
	hid.Initialize()

	log.SetSeverity(config.LogLevel())
	log.SetOutput(config.LogFile())

	err := run()
	if err != nil {
		log.Fatalf("%s", err)
	}
	log.Info("Shutdown complete.")
}
