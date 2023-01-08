package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/Bananenpro/log"

	"github.com/go-chi/chi/v5"
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
		log.Fatal("Failed to connect to database:", err)
	}
	userRepo := db.NewUserRepository()

	handler.AuthService = services.NewAuthService(userRepo)
	handler.UserService = services.NewUserService(userRepo, handler.AuthService)

	handler.Router = chi.NewRouter()
	handler.RegisterMiddlewares()
	handler.RegisterRoutes()

	port := config.Port()

	addr := fmt.Sprintf(":%d", port)
	log.Infof("Listening on %s...", addr)
	return http.ListenAndServe(addr, handler)
}

func main() {
	godotenv.Load()

	log.SetSeverity(config.LogLevel())
	log.SetOutput(config.LogFile())

	err := run()
	if err != nil {
		log.Errorf("%s", err)
		os.Exit(1)
	}
}
