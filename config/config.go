package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/juho05/log"
)

var values = make(map[string]any)

func AutoMigrate() (b bool) {
	if c, ok := values["AUTO_MIGRATE"]; ok {
		return c.(bool)
	}
	defer func() {
		values["AUTO_MIGRATE"] = b
	}()
	str := os.Getenv("AUTO_MIGRATE")
	b, _ = strconv.ParseBool(str)
	return b
}

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
	def := "file:database.sqlite?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(3000)"
	con = os.Getenv("DB_CONNECTION")
	if con == "" {
		return def
	}
	os.MkdirAll(filepath.Dir(con), 0o755)
	return con
}

func TLSCert() (path string) {
	if c, ok := values["TLS_CERT"]; ok {
		return c.(string)
	}
	defer func() {
		values["TLS_CERT"] = path
	}()
	path = os.Getenv("TLS_CERT")
	if path == "" {
		return ""
	}
	return path
}

func TLSKey() (path string) {
	if c, ok := values["TLS_KEY"]; ok {
		return c.(string)
	}
	defer func() {
		values["TLS_KEY"] = path
	}()
	return os.Getenv("TLS_KEY")
}

func EmailUsername() (username string) {
	if n, ok := values["EMAIL_USERNAME"]; ok {
		return n.(string)
	}
	defer func() {
		values["EMAIL_USERNAME"] = username
	}()
	return os.Getenv("EMAIL_USERNAME")
}

func EmailPassword() (password string) {
	if n, ok := values["EMAIL_PASSWORD"]; ok {
		return n.(string)
	}
	defer func() {
		values["EMAIL_PASSWORD"] = password
	}()
	return os.Getenv("EMAIL_PASSWORD")
}

func EmailHost() (host string) {
	if n, ok := values["EMAIL_HOST"]; ok {
		return n.(string)
	}
	defer func() {
		values["EMAIL_HOST"] = host
	}()
	host = os.Getenv("EMAIL_HOST")
	if !strings.Contains(host, ":") {
		host += ":587"
	}
	return host
}

func ProfilePictureDir() (dir string) {
	if d, ok := values["PROFILE_PICTURE_DIR"]; ok {
		return d.(string)
	}
	defer func() {
		values["PROFILE_PICTURE_DIR"] = dir
	}()
	def := "./profile_pictures"
	dir = os.Getenv("PROFILE_PICTURE_DIR")
	if dir == "" {
		dir = def
	}

	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		log.Errorf("Couldn't create profile picture directory (%s): %s", dir, err)
	}

	return dir
}

func ProfilePictureSize() (size int) {
	if s, ok := values["PROFILE_PICTURE_SIZE"]; ok {
		return s.(int)
	}
	defer func() {
		values["PROFILE_PICTURE_SIZE"] = size
	}()
	def := 1024
	sizeStr := os.Getenv("PROFILE_PICTURE_SIZE")
	if sizeStr == "" {
		return def
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		log.Errorf("Invalid profile picture size '%s': not a number. Using default: %d", sizeStr, def)
		return def
	}
	return size
}

func BaseURL() (u string) {
	if v, ok := values["BASE_URL"]; ok {
		return v.(string)
	}
	defer func() {
		values["BASE_URL"] = u
	}()
	u = os.Getenv("BASE_URL")
	if u == "" {
		log.Fatal("BASE_URL must not be empty")
	}
	return strings.TrimSuffix(u, "/")
}

func HCaptchaSiteKey() (key string) {
	if k, ok := values["HCAPTCHA_SITE_KEY"]; ok {
		return k.(string)
	}
	defer func() {
		values["HCAPTCHA_SITE_KEY"] = key
	}()
	key = os.Getenv("HCAPTCHA_SITE_KEY")

	if key == "" {
		log.Warn("Empty HCAPTCHA_SITE_KEY. CAPTCHA verification is disabled.")
	}

	return key
}

func HCaptchaSecret() (secret string) {
	if s, ok := values["HCAPTCHA_SECRET"]; ok {
		return s.(string)
	}
	defer func() {
		values["HCAPTCHA_SECRET"] = secret
	}()
	return os.Getenv("HCAPTCHA_SECRET")
}
