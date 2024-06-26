package config

import (
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

func Local() (b bool) {
	if c, ok := values["LOCAL"]; ok {
		return c.(bool)
	}
	defer func() {
		values["LOCAL"] = b
	}()
	str := os.Getenv("LOCAL")
	b, _ = strconv.ParseBool(str)
	return b
}

func InviteOnly() (b bool) {
	if c, ok := values["INVITE_ONLY"]; ok {
		return c.(bool)
	}
	defer func() {
		values["INVITE_ONLY"] = b
	}()
	str := os.Getenv("INVITE_ONLY")
	b, _ = strconv.ParseBool(str)
	return b
}

func BehindProxy() (b bool) {
	if c, ok := values["BEHIND_PROXY"]; ok {
		return c.(bool)
	}
	defer func() {
		values["BEHIND_PROXY"] = b
	}()
	str := os.Getenv("BEHIND_PROXY")
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

func DBFile() (f string) {
	if c, ok := values["DB_FILE"]; ok {
		return c.(string)
	}
	defer func() {
		values["DB_FILE"] = f
	}()
	def := "database.sqlite"
	f = os.Getenv("DB_FILE")
	if f == "" {
		return def
	}
	os.MkdirAll(filepath.Dir(f), 0o755)
	return f
}

func PostgresHost() (f string) {
	if c, ok := values["POSTGRES_HOST"]; ok {
		return c.(string)
	}
	defer func() {
		values["POSTGRES_HOST"] = f
	}()
	def := ""
	f = os.Getenv("POSTGRES_HOST")
	if f == "" {
		return def
	}
	return f
}

func PostgresPort() (p int) {
	if s, ok := values["POSTGRES_PORT"]; ok {
		return s.(int)
	}
	defer func() {
		values["POSTGRES_PORT"] = p
	}()
	def := 5432
	portStr := os.Getenv("POSTGRES_PORT")
	if portStr == "" {
		return def
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		log.Fatal("Invalid POSTGRES_PORT value")
	}
	return p
}

func PostgresDB() (f string) {
	if c, ok := values["POSTGRES_DB"]; ok {
		return c.(string)
	}
	defer func() {
		values["POSTGRES_DB"] = f
	}()
	def := "hid"
	f = os.Getenv("POSTGRES_DB")
	if f == "" {
		return def
	}
	return f
}

func PostgresUser() (f string) {
	if c, ok := values["POSTGRES_USER"]; ok {
		return c.(string)
	}
	defer func() {
		values["POSTGRES_USER"] = f
	}()
	def := "hid"
	f = os.Getenv("POSTGRES_USER")
	if f == "" {
		return def
	}
	return f
}

func PostgresPassword() (f string) {
	if c, ok := values["POSTGRES_PASSWORD"]; ok {
		return c.(string)
	}
	defer func() {
		values["POSTGRES_PASSWORD"] = f
	}()
	f = os.Getenv("POSTGRES_PASSWORD")
	if f == "" {
		log.Fatal("POSTGRES_PASSWORD must not be empty when providing POSTGRES_HOST")
	}
	return f
}

func SessionLifetime() (d time.Duration) {
	if a, ok := values["SESSION_LIFETIME"]; ok {
		return a.(time.Duration)
	}
	defer func() {
		values["SESSION_LIFETIME"] = d
	}()
	def := 3 * 24 * time.Hour
	durStr := os.Getenv("SESSION_LIFETIME")
	if durStr == "" {
		return def
	}
	d, err := time.ParseDuration(durStr)
	if err != nil {
		log.Errorf("invalid SESSION_LIFETIME: %s", err)
		return def
	}
	if d < time.Minute {
		log.Errorf("invalid SESSION_LIFETIME: session lifetime must not be < 1min")
		return def
	}
	return d
}

func SessionIdleTimeout() (d time.Duration) {
	if a, ok := values["SESSION_IDLE_TIMEOUT"]; ok {
		return a.(time.Duration)
	}
	defer func() {
		values["SESSION_IDLE_TIMEOUT"] = d
	}()
	def := 24 * time.Hour
	durStr := os.Getenv("SESSION_IDLE_TIMEOUT")
	if durStr == "" {
		return def
	}
	d, err := time.ParseDuration(durStr)
	if err != nil {
		log.Errorf("invalid SESSION_IDLE_TIMEOUT: %s", err)
		return def
	}
	if d < time.Minute {
		log.Errorf("invalid SESSION_IDLE_TIMEOUT: session idle timeout must not be < 1min")
		return def
	}
	return d
}

func AuthGatewayConfig() (path string) {
	if c, ok := values["AUTH_GATEWAY_CONFIG"]; ok {
		return c.(string)
	}
	defer func() {
		values["AUTH_GATEWAY_CONFIG"] = path
	}()
	path = os.Getenv("AUTH_GATEWAY_CONFIG")
	if path == "" {
		return ""
	}
	return path
}

func AuthGatewayDomain() (d string) {
	if c, ok := values["AUTH_GATEWAY_DOMAIN"]; ok {
		return c.(string)
	}
	defer func() {
		values["AUTH_GATEWAY_DOMAIN"] = d
	}()
	def := Domain()
	d = os.Getenv("AUTH_GATEWAY_DOMAIN")
	if d == "" {
		return def
	}
	return d
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

func Domain() (d string) {
	u, err := url.Parse(BaseURL())
	if err != nil {
		log.Errorf("Invalid base URL: %w. Using raw base URL as domain value.")
		return BaseURL()
	}
	return u.Hostname()
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
