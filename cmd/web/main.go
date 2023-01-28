package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Bananenpro/log"
	"github.com/alexedwards/scs/v2"

	hid "github.com/Bananenpro/h-id"

	"github.com/joho/godotenv"

	"github.com/Bananenpro/h-id/config"
	"github.com/Bananenpro/h-id/handlers"
	"github.com/Bananenpro/h-id/repos/sqlite"
	"github.com/Bananenpro/h-id/services"
)

func run() error {
	handler := handlers.NewHandler()

	db, err := sqlite.Connect(config.DBConnection())
	if err != nil {
		return fmt.Errorf("Failed to connect to database:", err)
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
	log.Infof("Listening on %s...", addr)

	if cert != "" && key != "" {
		return http.ListenAndServeTLS(addr, cert, key, handler)
	} else {
		return http.ListenAndServe(addr, handler)
	}
}

func main() {
	godotenv.Load()

	log.SetSeverity(config.LogLevel())
	log.SetOutput(config.LogFile())

	err := run()
	if err != nil {
		log.Fatalf("%s", err)
	}
}
