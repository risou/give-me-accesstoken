package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

type Option struct {
	ConfigFile string
	ConfigSet  string
	RawOutput  bool
	Version    bool
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type AuthRequestParams struct {
	ClientID    string
	RedirectURI string
	Scopes      []string
}

type RedirectParams struct {
	Code  string
	State string
	Error error
}

func generateRandomState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func generateAuthURL(conf *Config, state string) string {
	queryParams := url.Values{}
	queryParams.Set("response_type", "code")
	queryParams.Set("client_id", conf.ClientID)
	queryParams.Set("redirect_uri", conf.RedirectURI)
	queryParams.Set("scope", strings.Join(conf.Scopes, " "))
	queryParams.Set("state", state)

	return conf.AuthEndpoint + "?" + queryParams.Encode()
}

func generateTokenRequestParams(conf *Config, code string) (url.Values, error) {
	data := url.Values{}

	data.Set("grant_type", conf.GrantType)
	data.Set("client_id", conf.ClientID)
	data.Set("redirect_uri", conf.RedirectURI)
	data.Set("scope", strings.Join(conf.Scopes, " "))
	if conf.GrantType == "authorization_code" {
		data.Set("code", code)
	}

	if conf.ClientSecret != "" {
		// client_secret_post
		data.Set("client_secret", conf.ClientSecret)
	} else {
		// private_key_jwt
		clientAssertion, err := generateClientAssertion(*conf)
		if err != nil {
			return nil, fmt.Errorf("failed to generate client assertion: %s", err)
		}
		data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Set("client_assertion", string(clientAssertion))
	}

	return data, nil
}

func generateClientAssertion(config Config) ([]byte, error) {
	keySet := jwk.NewSet()
	if err := json.Unmarshal([]byte(config.PrivateKeyJwt.Key), &keySet); err != nil {
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
	token.Set(jwt.AudienceKey, config.PrivateKeyJwt.JWTClaims.Audience)
	token.Set(jwt.IssuedAtKey, currentTime.Unix())
	token.Set(jwt.ExpirationKey, currentTime.Add(time.Hour).Unix())
	token.Set(jwt.JwtIDKey, uuid.New().String())

	signed, err := jwt.Sign(token, jwa.SignatureAlgorithm(config.PrivateKeyJwt.Alg), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %s", err)
	}

	return signed, nil
}

func openBrowser(url string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	return err
}

// authorizationRequest handles the authorization process for the authorization code grant flow.
// It is specifically designed for this grant type and does not support the implicit grant flow.
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

func tokenRequest(endpoint string, data url.Values) (*TokenResponse, error) {
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %s", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

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
		return nil, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	return &tokenResponse, nil
}

func authenticateAndRedirect(conf *Config) (string, error) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	redirectChan := make(chan RedirectParams, 1)

	parsedURL, err := url.Parse(conf.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse redirect_uri: %s", err)
	}

	startLocalServer(wg, ctx, redirectChan, parsedURL.Port(), parsedURL.Path)

	state := generateRandomState()

	openBrowser(generateAuthURL(conf, state))

	var code string

	select {
	case redirectParams := <-redirectChan:
		if redirectParams.Error != nil {
			return "", fmt.Errorf("failed to receive redirect params: %s", redirectParams.Error)
		}
		if state != redirectParams.State {
			return "", fmt.Errorf("state mismatch")
		}
		code = redirectParams.Code
	case <-ctx.Done():
		return "", fmt.Errorf("timeout")
	}

	wg.Wait()

	return code, nil
}

func authenticateAndAuthorize(conf *Config) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create cookie jar: %s", err)
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
		return "", fmt.Errorf("failed to create request: %s", err)
	}

	resp, err := client.Do(loginReq)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("failed to login: %s", resp.Status)
	}

	arParams := AuthRequestParams{
		ClientID:    conf.ClientID,
		RedirectURI: conf.RedirectURI,
		Scopes:      conf.Scopes,
	}

	code, err := authorizationRequest(client, conf.AuthEndpoint, arParams)
	if err != nil {
		return "", fmt.Errorf("failed to request authorization: %s", err)
	}

	return *code, nil
}

func executeAuthorizationCodeFlow(conf *Config) (*TokenResponse, error) {
	var code string
	var err error
	if conf.Login.LoginEndpoint == "" {
		// login with browser
		code, err = authenticateAndRedirect(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to request authorization: %s", err)
		}
	} else {
		// login with API
		code, err = authenticateAndAuthorize(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to request authorization: %s", err)
		}
	}

	data, err := generateTokenRequestParams(conf, code)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token request params: %s", err)
	}

	tokenResponse, err := tokenRequest(conf.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("failed to request token: %s", err)
	}

	return tokenResponse, nil
}

func executeClientCredentialsFlow(conf *Config) (*TokenResponse, error) {
	data, err := generateTokenRequestParams(conf, "")
	if err != nil {
		return nil, fmt.Errorf("failed to generate token request params: %s", err)
	}

	tokenResponse, err := tokenRequest(conf.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("failed to request token: %s", err)
	}

	return tokenResponse, nil
}

func startLocalServer(wg *sync.WaitGroup, ctx context.Context, redirectChan chan RedirectParams, port string, path string) *http.Server {
	if port == "" {
		port = "80"
	}
	srv := &http.Server{Addr: ":" + port}

	var mu sync.Mutex
	var redirectReceived bool

	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		redirectReceived = true
		mu.Unlock()

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		redirectChan <- RedirectParams{
			Code:  code,
			State: state,
		}

		fmt.Fprintf(w, "<html><script>window.close();</script><body>Close this window.</body></html>")

		wg.Done()

		go func() {
			if err := srv.Shutdown(context.Background()); err != nil {
				redirectChan <- RedirectParams{
					Error: err,
				}
			}
		}()
	})

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			redirectChan <- RedirectParams{
				Error: err,
			}
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
			mu.Lock()
			if !redirectReceived {
				wg.Done()
				if err := srv.Shutdown(context.Background()); err != nil {
					redirectChan <- RedirectParams{
						Error: err,
					}
				}
			}
			mu.Unlock()
		}
	}()

	return srv
}

func Run(option Option) error {

	conf, err := loadConfig(option.ConfigFile, option.ConfigSet)
	if err != nil {
		return err
	}

	if conf == nil {
		return fmt.Errorf("failed to load config")
	}

	var result *TokenResponse

	switch conf.GrantType {
	case "authorization_code":
		result, err = executeAuthorizationCodeFlow(conf)
	case "client_credentials":
		result, err = executeClientCredentialsFlow(conf)
	default:
		return fmt.Errorf("unsupported authorization grant: %s", conf.GrantType)
	}
	if err != nil {
		return err
	}

	if option.RawOutput {
		fmt.Println(result.AccessToken)
	} else {
		fmt.Printf("access_token: %s\n", result.AccessToken)
	}

	return err
}
