package services

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/juho05/h-id/config"
	"github.com/oklog/ulid/v2"
)

type AuthGatewayService interface {
	IsAuthorized(userID ulid.ULID, domain string) bool
	IsAllowedURL(url string) bool
	IsAllowedDomain(url string) bool
}

type domainConfig struct {
	users  map[string]struct{}
	groups map[string]struct{}
}

type userConfig struct {
	name   string
	groups []string
}

type authGatewayService struct {
	users   map[ulid.ULID]userConfig
	domains map[string]domainConfig
}

func NewAuthGatewayService() (AuthGatewayService, error) {
	a := &authGatewayService{
		users:   make(map[ulid.ULID]userConfig),
		domains: make(map[string]domainConfig),
	}
	err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (a *authGatewayService) IsAuthorized(userID ulid.ULID, domain string) bool {
	d, ok := a.findDomainConfig(domain)
	if !ok {
		return false
	}
	user, ok := a.users[userID]
	if !ok {
		return false
	}
	if _, ok := d.users[user.name]; ok {
		return true
	}
	for _, group := range user.groups {
		if _, ok := d.groups[group]; ok {
			return true
		}
	}
	return false
}

func (a *authGatewayService) IsAllowedURL(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || !u.IsAbs() || u.Hostname() == "" {
		return false
	}
	return a.IsAllowedDomain(u.Hostname())
}

func (a *authGatewayService) IsAllowedDomain(domain string) bool {
	_, ok := a.findDomainConfig(domain)
	return ok
}

func (a *authGatewayService) findDomainConfig(domain string) (domainConfig, bool) {
	if domain == "" {
		return domainConfig{}, false
	}
	d, ok := a.domains[domain]
	for !ok {
		parts := strings.Split(domain, ".")
		if parts[0] == "*" {
			if len(parts) == 1 {
				return domainConfig{}, false
			}
			parts = parts[1:]
		}
		parts[0] = "*"
		domain = strings.Join(parts, ".")
		d, ok = a.domains[domain]
	}
	return d, ok
}

func (a *authGatewayService) loadConfig() error {
	if config.AuthGatewayConfig() == "" {
		return nil
	}
	file, err := os.Open(config.AuthGatewayConfig())
	if err != nil {
		return fmt.Errorf("load auth gateway config: %w", err)
	}
	defer file.Close()
	type conf struct {
		AllowedDomains []string `json:"allowedDomains"`
		Users          map[string]struct {
			ID     string   `json:"id"`
			Groups []string `json:"groups"`
		} `json:"users"`
		Domains map[string]struct {
			Users  []string `json:"users"`
			Groups []string `json:"groups"`
		}
	}
	var c conf
	err = json.NewDecoder(file).Decode(&c)
	if err != nil {
		return fmt.Errorf("load auth gateway config: %w", err)
	}
	for name, u := range c.Users {
		id, err := ulid.Parse(u.ID)
		if err != nil {
			return fmt.Errorf("load auth gateway config: load user config %s: invalid id: %w", name, err)
		}
		if u.Groups == nil {
			u.Groups = make([]string, 0)
		}
		a.users[id] = userConfig{
			name:   name,
			groups: u.Groups,
		}
	}
	for name, d := range c.Domains {
		domainConf := domainConfig{
			users:  make(map[string]struct{}),
			groups: make(map[string]struct{}),
		}
		for _, user := range d.Users {
			domainConf.users[user] = struct{}{}
		}
		for _, group := range d.Groups {
			domainConf.groups[group] = struct{}{}
		}
		a.domains[name] = domainConf
	}
	return nil
}
