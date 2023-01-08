package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/Bananenpro/log"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"

	"github.com/Bananenpro/h-id/handlers"
)

type options struct {
	port int
}

func run() error {
	handler := handlers.NewHandler()
	handler.Router = chi.NewRouter()

	handler.RegisterMiddlewares()
	handler.RegisterRoutes()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := fmt.Sprintf(":%s", port)
	log.Infof("Listening on %s...", addr)
	return http.ListenAndServe(addr, handler)
}

func initLogger() {
	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		level = "4"
	}
	l, err := strconv.Atoi(level)
	if err != nil || l < 0 || l > 5 {
		log.Error("Invalid log level. Valid values: 0 (none), 1 (fatal), 2 (error), 3 (warning), 4 (info), 5 (trace)")
	}
	log.SetSeverity(log.Severity(l))

	if os.Getenv("LOG_FILE") != "" {
		appnd, _ := strconv.ParseBool(os.Getenv("LOG_APPEND"))
		if appnd {
			file, err := os.Open(os.Getenv("LOG_FILE"))
			if err != nil {
				log.Fatalf("Failed to open log file %s", err)
			}
			log.SetOutput(file)
		} else {
			file, err := os.Create(os.Getenv("LOG_FILE"))
			if err != nil {
				log.Fatalf("Failed to create log file %s", err)
			}
			log.SetOutput(file)
		}
	}
}

func main() {
	godotenv.Load()
	initLogger()

	err := run()
	if err != nil {
		log.Errorf("%s", err)
		os.Exit(1)
	}
}
