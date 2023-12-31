package app

import (
	"gopkg.in/yaml.v3"
	"log"
	"os"
)

type Config struct {
	ClientID      string   `yaml:"client_id"`
	RedirectURI   string   `yaml:"redirect_uri"`
	TokenEndpoint string   `yaml:"token_endpoint"`
	Alg           string   `yaml:"algorithm"`
	Key           string   `yaml:"key"`
	Scopes        []string `yaml:"scopes"`
}

func LoadConfig(file string, configSet string) *Config {
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
