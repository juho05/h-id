package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	hid "github.com/juho05/h-id"
	"github.com/juho05/h-id/config"
	"github.com/juho05/h-id/repos"
	"github.com/juho05/h-id/repos/sqlite"
	"github.com/juho05/log"
	"github.com/oklog/ulid/v2"
)

func setAdmin(userRepo repos.UserRepository, args []string) error {
	if len(args) < 2 {
		fmt.Println("USAGE h-id-cli set-admin <user_id> <true|false>")
		os.Exit(1)
	}
	userID, err := ulid.Parse(args[0])
	if err != nil {
		fmt.Println("USAGE h-id-cli set-admin <user_id> <true|false>")
		return fmt.Errorf("invalid user_id: %w", err)
	}
	admin, err := strconv.ParseBool(args[1])
	if err != nil {
		fmt.Println("USAGE h-id-cli set-admin <user_id> <true|false>")
		return fmt.Errorf("invalid boolean: %w", err)
	}
	err = userRepo.UpdateAdminStatus(context.Background(), userID, admin)
	if err != nil {
		if errors.Is(err, repos.ErrNoRecord) {
			err = fmt.Errorf("user with ID %s does not exist", userID.String())
		}
		return err
	}
	return nil
}

func run(args []string) error {
	db, err := sqlite.Connect(config.DBConnection())
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer db.Close()
	userRepo := db.NewUserRepository()
	if len(args) == 0 {
		fmt.Println(`USAGE h-id-cli <command>
COMMANDS
		- set-admin
		`)
		os.Exit(1)
	}
	switch args[0] {
	case "set-admin":
		err = setAdmin(userRepo, args[1:])
	default:
		err = fmt.Errorf("unknown command: %s", args[0])
	}
	return err
}

func main() {
	godotenv.Load()
	hid.Initialize()

	log.SetSeverity(config.LogLevel())
	log.SetOutput(config.LogFile())

	err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		os.Exit(1)
	}
	fmt.Println("Done.")
}
