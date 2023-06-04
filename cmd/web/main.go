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

	"github.com/Bananenpro/log"
	"github.com/alexedwards/scs/v2"

	hid "github.com/juho05/h-id"

	"github.com/joho/godotenv"

	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/handlers"
	"github.com/juho05/h-id/repos/sqlite"
	"github.com/juho05/h-id/services"
)

func run() error {
	handler := handlers.NewHandler()

	db, err := sqlite.Connect(config.DBConnection())
	if err != nil {
		return fmt.Errorf("Failed to connect to database: %w", err)
	}
	defer db.Close()

	userRepo := db.NewUserRepository()
	tokenRepo := db.NewTokenRepository()
	clientRepo := db.NewClientRepository()
	oauthRepo := db.NewOAuthRepository()

	handler.SessionManager = scs.New()
	handler.SessionManager.Store = db.NewSessionRepository()
	handler.SessionManager.Lifetime = 72 * time.Hour
	handler.SessionManager.IdleTimeout = 12 * time.Hour
	handler.SessionManager.Cookie.Secure = true

	emailService := services.NewEmailService(hid.EmailFS)

	handler.AuthService = services.NewAuthService(userRepo, tokenRepo, oauthRepo, clientRepo, handler.SessionManager, emailService)
	handler.UserService = services.NewUserService(userRepo, handler.AuthService)
	handler.ClientService = services.NewClientService(clientRepo)

	handler.Renderer, err = handlers.NewRenderer(hid.HTMLFS)
	if err != nil {
		return fmt.Errorf("Failed to initialize renderer: %w", err)
	}

	handler.StaticFS = hid.StaticFS
	handler.RegisterRoutes()

	port := config.Port()

	cert := config.TLSCert()
	key := config.TLSKey()

	addr := fmt.Sprintf(":%d", port)
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

	log.Infof("Listening on %s...", addr)

	if cert != "" && key != "" {
		err = server.ListenAndServeTLS(cert, key)
	} else {
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
