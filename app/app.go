package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
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

func generateRandomState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
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
	token.Set(jwt.AudienceKey, config.JWTClaims.Audience)
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

func tokenRequest(config Config, clientAssertion string) (*TokenResponse, error) {
	data := url.Values{}

	data.Set("grant_type", "client_credentials")
	data.Set("client_id", config.ClientID)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", clientAssertion)
	data.Set("redirect_uri", config.RedirectURI)
	data.Set("scope", strings.Join(config.Scopes, " "))

	req, err := http.NewRequest("POST", config.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %s", err)
		log.Fatalf("Failed to create request: %s", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %s", err)
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed tu unmarshal response: %s", err)
	}

	return &tokenResponse, nil
}

func executeAuthorizationCodeFlow(conf *Config) (*TokenResponse, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %s", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	loginReq, err := http.NewRequest("POST", conf.Login.LoginEndpoint, bytes.NewBuffer([]byte(conf.Login.AuthInfo)))
	loginReq.Header.Set("Content-Type", "application/json")
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %s", err)
	}

	_, err = client.Do(loginReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %s", err)
	}

	state := generateRandomState()

	queryParams := url.Values{}
	queryParams.Set("response_type", "code")
	queryParams.Set("client_id", conf.ClientID)
	queryParams.Set("redirect_uri", conf.RedirectURI)
	queryParams.Set("scope", strings.Join(conf.Scopes, " "))
	queryParams.Set("state", state)

	authURL := conf.AuthEndpoint + "?" + queryParams.Encode()

	log.Printf("[debug] Auth URL: %s", authURL)

	authReq, err := http.NewRequest("GET", authURL, nil)
	authReq.Header.Set("Content-Type", "application/json")
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %s", err)
	}

	authResp, err := client.Do(authReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %s", err)
	}
	defer authResp.Body.Close()

	var code string
	if location, ok := authResp.Header["Location"]; ok && len(location) > 0 {
		locationURL, err := url.Parse(location[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse location: %s", err)
		}
		code = locationURL.Query().Get("code")
	} else {
		return nil, fmt.Errorf("failed to get code")
	}

	log.Printf("[debug] Code: %s", code)

	clientAssertion, err := generateClientAssertion(*conf)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client assertion: %s", err)
	}

	log.Printf("[debug] Signed token: %s", clientAssertion)

	// TODO: refactor the following code and TokenRequest()
	data := url.Values{}

	data.Set("grant_type", "authorization_code")
	data.Set("client_id", conf.ClientID)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", string(clientAssertion))
	data.Set("redirect_uri", conf.RedirectURI)
	data.Set("scope", strings.Join(conf.Scopes, " "))
	data.Set("code", code)

	req, err := http.NewRequest("POST", conf.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %s", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %s", err)
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed tu unmarshal response: %s", err)
	}

	log.Printf("[debug] Token Response: %#v", tokenResponse)
	log.Printf("[debug] Access Token: %s", tokenResponse.AccessToken)

	return &tokenResponse, nil
}

func executeClientCredentialsFlow(conf *Config) (*TokenResponse, error) {
	signed, err := generateClientAssertion(*conf)

	if err != nil {
		return nil, fmt.Errorf("failed to generate client assertion: %s", err)
	}

	log.Printf("[debug] Signed token: %s", signed)

	res, err := tokenRequest(*conf, string(signed))

	if err != nil {
		return nil, fmt.Errorf("failed to request token: %s", err)
	}

	log.Printf("[debug] Access Token: %s", res.AccessToken)

	return res, nil
}

func Run(option Option) error {

	conf := loadConfig(option.ConfigFile, option.ConfigSet)

	if conf == nil {
		log.Fatalf("Failed to load config")
	}

	var result *TokenResponse
	var err error

	switch conf.GrantType {
	case "authorization_code":
		log.Printf("[debug] Authorization Code Grant")
		result, err = executeAuthorizationCodeFlow(conf)
	case "client_credentials":
		log.Printf("[debug] Client Credentials Grant")
		result, err = executeClientCredentialsFlow(conf)
	default:
		return fmt.Errorf("unsupported authorization grant: %s", conf.GrantType)
	}

	log.Printf("[debug] Result: %#v", result)

	return err
}
