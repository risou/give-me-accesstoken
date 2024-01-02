package app

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	GrantType     string   `yaml:"grant_type"`
	Login         Login    `yaml:"login"`
	ClientID      string   `yaml:"client_id"`
	RedirectURI   string   `yaml:"redirect_uri"`
	AuthEndpoint  string   `yaml:"authorization_endpoint"`
	TokenEndpoint string   `yaml:"token_endpoint"`
	JWTClaims     JWTClaim `yaml:"jwt_claims"`
	Alg           string   `yaml:"algorithm"`
	Key           string   `yaml:"key"`
	Scopes        []string `yaml:"scopes"`
}

type Login struct {
	AuthInfo      string `yaml:"auth_info"`
	LoginEndpoint string `yaml:"login_endpoint"`
}

type JWTClaim struct {
	Audience string `yaml:"audience"`
}

func loadConfig(file string, configSet string) *Config {
	data, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("Failed to read config file: %s", err)
	}

	configs := make(map[string]Config)
	if err := yaml.Unmarshal(data, &configs); err != nil {
		log.Fatalf("Failed to unmarshal config file: %s", err)
	}

	for key, config := range configs {
		if key == configSet {
			log.Printf("[debug] Config: %#v", config)
			return &config
		}
	}
	return nil
}
