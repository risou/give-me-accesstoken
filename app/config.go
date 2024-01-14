package app

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	GrantType     string              `yaml:"grant_type"`
	Login         Login               `yaml:"login"`
	ClientID      string              `yaml:"client_id"`
	ClientSecret  string              `yaml:"client_secret"`
	RedirectURI   string              `yaml:"redirect_uri"`
	AuthEndpoint  string              `yaml:"authorization_endpoint"`
	TokenEndpoint string              `yaml:"token_endpoint"`
	PrivateKeyJwt PrivateKeyJwtConfig `yaml:"private_key_jwt"`
	Scopes        []string            `yaml:"scopes"`
}

type Login struct {
	AuthInfo      string `yaml:"auth_info"`
	LoginEndpoint string `yaml:"login_endpoint"`
}

type JWTClaim struct {
	Audience string `yaml:"audience"`
}

type PrivateKeyJwtConfig struct {
	JWTClaims JWTClaim `yaml:"jwt_claims"`
	Alg       string   `yaml:"algorithm"`
	Key       string   `yaml:"key"`
}

func loadConfig(file string, configSet string) (*Config, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %s", err)
	}

	configs := make(map[string]Config)
	if err := yaml.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %s", err)
	}

	for key, config := range configs {
		if key == configSet {
			return &config, nil
		}
	}

	return nil, nil
}
