package app

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Option struct {
	ConfigFile string
	ConfigSet  string
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func generateClientAssertion(config Config) ([]byte, error) {
	keySet := jwk.NewSet()
	if err := json.Unmarshal([]byte(config.Key), &keySet); err != nil {
		log.Fatalf("Failed to unmarshal private key: %s", err)
	}

	var privateKey jwk.Key
	found := false

	for it := keySet.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		privateKey = pair.Value.(jwk.Key)
		found = true
		if found {
			break
		}
	}

	currentTime := time.Now()

	token := jwt.New()

	token.Set(jwt.IssuerKey, config.ClientID)
	token.Set(jwt.SubjectKey, config.ClientID)
	token.Set(jwt.AudienceKey, config.TokenEndpoint)
	token.Set(jwt.IssuedAtKey, currentTime.Unix())
	token.Set(jwt.ExpirationKey, currentTime.Add(time.Hour).Unix())
	token.Set(jwt.JwtIDKey, uuid.New().String())

	signed, err := jwt.Sign(token, jwa.SignatureAlgorithm(config.Alg), privateKey)
	if err != nil {
		log.Fatalf("Failed to sign token: %s", err)
		return nil, err
	}

	return signed, nil
}

func tokenRequest(config Config, clientAssertion string) (TokenResponse, error) {
	data := url.Values{}

	data.Set("grant_type", "client_credentials")
	data.Set("client_id", config.ClientID)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", clientAssertion)
	data.Set("redirect_uri", config.RedirectURI)
	data.Set("scope", strings.Join(config.Scopes, " "))

	req, err := http.NewRequest("POST", config.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatalf("Failed to create request: %s", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %s", err)
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		log.Fatalf("Failed to unmarshal response: %s", err)
	}

	return tokenResponse, nil
}

func Run(option Option) error {

	conf := loadConfig(option.ConfigFile, option.ConfigSet)

	if conf == nil {
		log.Fatalf("Failed to load config")
	}

	signed, err := generateClientAssertion(*conf)

	if err != nil {
		log.Fatalf("Failed to generate client assertion: %s", err)
	}

	log.Printf("[debug] Signed token: %s", signed)

	res, err := tokenRequest(*conf, string(signed))

	if err != nil {
		log.Fatalf("Failed to request token: %s", err)
	}

	log.Printf("[debug] Access Token: %s", res.AccessToken)

	return nil
}
