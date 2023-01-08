package config

import (
	"os"
	"strconv"

	"github.com/Bananenpro/log"
)

var values = make(map[string]any)

func Port() (port int) {
	if p, ok := values["PORT"]; ok {
		return p.(int)
	}
	defer func() {
		values["PORT"] = port
	}()
	def := 8080
	portStr := os.Getenv("PORT")
	if portStr == "" {
		return def
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Errorf("Invalid port '%s': not a number. Using default: %d", portStr, def)
		return def
	}
	return port
}

func LogLevel() (sev log.Severity) {
	if l, ok := values["LOG_LEVEL"]; ok {
		return l.(log.Severity)
	}
	defer func() {
		values["LOG_LEVEL"] = sev
	}()
	def := log.INFO
	logLevelStr := os.Getenv("LOG_LEVEL")
	if logLevelStr == "" {
		return def
	}
	level, err := strconv.Atoi(logLevelStr)
	if err != nil {
		log.Errorf("Invalid log level '%s': not a number. Using default: %d", logLevelStr, def)
		return def
	}
	if level < int(log.NONE) || level > int(log.TRACE) {
		log.Errorf("Invalid log level. Valid values: 0 (none), 1 (fatal), 2 (error), 3 (warning), 4 (info), 5 (trace). Using default: %d", def)
		return def
	}
	return log.Severity(level)
}

func LogFile() (file *os.File) {
	if f, ok := values["LOG_FILE"]; ok {
		return f.(*os.File)
	}
	defer func() {
		values["LOG_FILE"] = file
	}()
	def := os.Stderr
	if os.Getenv("LOG_FILE") == "" {
		return def
	}
	appnd, _ := strconv.ParseBool(os.Getenv("LOG_APPEND"))
	if appnd {
		file, err := os.Open(os.Getenv("LOG_FILE"))
		if err != nil {
			log.Fatalf("Failed to open log file %s. Using default: STDERR", err)
			return def
		}
		return file
	} else {
		file, err := os.Create(os.Getenv("LOG_FILE"))
		if err != nil {
			log.Fatalf("Failed to create log file %s. Using default: STDERR", err)
			return def
		}
		return file
	}
}

func BcryptCost() (cost int) {
	if c, ok := values["BCRYPT_COST"]; ok {
		return c.(int)
	}
	defer func() {
		values["BCRYPT_COST"] = cost
	}()
	def := 12
	costStr := os.Getenv("BCRYPT_COST")
	if costStr == "" {
		return def
	}
	cost, err := strconv.Atoi(costStr)
	if err != nil {
		log.Errorf("Invalid bcrypt cost '%s': not a number. Using default: %d", costStr, def)
		return def
	}
	return cost
}

func DBConnection() (con string) {
	if c, ok := values["DB_CONNECTION"]; ok {
		return c.(string)
	}
	defer func() {
		values["DB_CONNECTION"] = con
	}()
	def := "database.sqlite?_foreign_keys=1"
	con = os.Getenv("DB_CONNECTION")
	if con == "" {
		return def
	}
	return con
}
