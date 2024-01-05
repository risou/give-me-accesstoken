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

type TokenRequestParams struct {
	GrantType       string
	Code            string
	RedirectURI     string
	ClientID        string
	Scopes          []string
	ClientAssertion string
}

type AuthRequestParams struct {
	ClientID    string
	RedirectURI string
	Scopes      []string
}

func generateRandomState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func generateClientAssertion(config Config) ([]byte, error) {
	keySet := jwk.NewSet()
	if err := json.Unmarshal([]byte(config.Key), &keySet); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %s", err)
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
		return nil, fmt.Errorf("failed to sign token: %s", err)
	}

	return signed, nil
}

func authorizationRequest(client *http.Client, endpoint string, p AuthRequestParams) (*string, error) {
	state := generateRandomState()

	queryParams := url.Values{}
	queryParams.Set("response_type", "code")
	queryParams.Set("client_id", p.ClientID)
	queryParams.Set("redirect_uri", p.RedirectURI)
	queryParams.Set("scope", strings.Join(p.Scopes, " "))
	queryParams.Set("state", state)

	authURL := endpoint + "?" + queryParams.Encode()

	req, err := http.NewRequest("GET", authURL, nil)
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %s", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %s", err)
	}
	defer resp.Body.Close()

	var code string
	if location, ok := resp.Header["Location"]; ok && len(location) > 0 {
		locationURL, err := url.Parse(location[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse location: %s", err)
		}
		s := locationURL.Query().Get("state")
		if s != state {
			return nil, fmt.Errorf("state mismatch")
		}
		code = locationURL.Query().Get("code")
	} else {
		return nil, fmt.Errorf("failed to get code")
	}

	return &code, nil
}

func tokenRequest(endpoint string, p TokenRequestParams) (*TokenResponse, error) {
	data := url.Values{}

	data.Set("grant_type", p.GrantType)
	data.Set("client_id", p.ClientID)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", p.ClientAssertion)
	data.Set("redirect_uri", p.RedirectURI)
	data.Set("scope", strings.Join(p.Scopes, " "))
	if p.GrantType == "authorization_code" {
		data.Set("code", p.Code)
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %s", err)
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

	arParams := AuthRequestParams{
		ClientID:    conf.ClientID,
		RedirectURI: conf.RedirectURI,
		Scopes:      conf.Scopes,
	}

	code, err := authorizationRequest(client, conf.AuthEndpoint, arParams)
	if err != nil {
		return nil, fmt.Errorf("failed to request authorization: %s", err)
	}

	clientAssertion, err := generateClientAssertion(*conf)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client assertion: %s", err)
	}

	trParams := TokenRequestParams{
		GrantType:       "authorization_code",
		ClientID:        conf.ClientID,
		RedirectURI:     conf.RedirectURI,
		Scopes:          conf.Scopes,
		ClientAssertion: string(clientAssertion),
		Code:            *code,
	}

	tokenResponse, err := tokenRequest(conf.TokenEndpoint, trParams)
	if err != nil {
		return nil, fmt.Errorf("failed to request token: %s", err)
	}

	return tokenResponse, nil
}

func executeClientCredentialsFlow(conf *Config) (*TokenResponse, error) {
	signed, err := generateClientAssertion(*conf)

	if err != nil {
		return nil, fmt.Errorf("failed to generate client assertion: %s", err)
	}

	params := TokenRequestParams{
		GrantType:       "client_credentials",
		ClientID:        conf.ClientID,
		RedirectURI:     conf.RedirectURI,
		Scopes:          conf.Scopes,
		ClientAssertion: string(signed),
	}

	res, err := tokenRequest(conf.TokenEndpoint, params)

	if err != nil {
		return nil, fmt.Errorf("failed to request token: %s", err)
	}

	return res, nil
}

func Run(option Option) error {

	conf := loadConfig(option.ConfigFile, option.ConfigSet)

	if conf == nil {
		return fmt.Errorf("failed to load config")
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
