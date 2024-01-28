# give-me-accesstoken

This is a command-line tool implemented in Go, providing a simple command to obtain access tokens from an authorization server in OAuth2.

**This tool is created to assist in software development that leverages OAuth2 authentication. Since it require you to include passwords or private keys in plain text in the config, it should never be used in a production environment or as part of an application.**

At present, it has been confirmed to work on macOS Sonoma, which is being used for development.

## Installation

```shell
go install github.com/risou/give-me-accesstoken@latest
```

## How to use

To query the authorization server, this command retrieves information from a config file.  
Please set up your config file as follows.

By default, the command expects a file named 'config.yml', but you can specify a file with any name using the `-f` option.

### Set up config file

This tool supports both the authorization code grant and client credentials grant. For each, please include the following information in the config file.

#### authorization code grant

Set an arbitrary name for 'key' to be specified at runtime.  
(In the following example, it is written as `name-of-something`)

When executing, use the `-c` option to specify the target 'key', which allows the tool to request an access token for the authorization server currently sought from the config file.  
By default, the tool expects a key named `local`, so if you are only registering one type, it is simpler to use `local` as the key.

```yaml
# client_secret_post
name-of-something:
  grant_type: 'authorization_code'
  client_id: <client_id>
  client_secret: <client_secret>
  redirect_uri: <redirect_uri>
  authorization_endpoint: <authorization_endpoint>
  token_endpoint: <token_endpoint>
  scopes:
    - "email"
```


```yaml
# private_key_jwt
name-of-something:
  grant_type: 'authorization_code'
  client_id: <client_id>
  redirect_uri: <redirect_uri>
  authorization_endpoint: <authorization_endpoint>
  token_endpoint: <token_endpoint>
  private_key_jwt:
    jwt_claims:
      audience: <audience>
    algorithm: 'RS256'
    key: '{"key": "value"}'
  scopes:
    - "openid"
    - "email"
```

```yaml
# use session cookie for authorization request
name-of-something:
  grant_type: 'authorization_code'
  login:
    auth_info: '{ "email": "username", "password": "password" }'
    login_endpoint: 'https://example.com/login'
  client_id: <client_id>
  client_secret: <client_secret>
  redirect_uri: <redirect_uri>
  authorization_endpoint: <authorization_endpoint>
  token_endpoint: <token_endpoint>
  scopes:
    - "email"
```

For each, set the following:

- grant_type
  - Set to `authorization_code`
- client_id
  - Enter the client ID issued by the authorization server
- client_secret
  - Enter the client secret issued by the authorization server
  - If this item is present, treat it as `client_secret_post` as the client authentication method
- redirect_uri
  - Enter the redirect URI registered with the authorization server
- authorization_endpoint
  - Enter the URL of the authorization endpoint
- token_endpoint
  - Enter the URL of the token endpoint
- private_key_jwt
  - Enter following items if you want to use the `private_key_jwt` format
  - jwt_claims
    - Set only 'audience' (aud) claim
    - To use the 'private_key_jwt' format for requesting an access token
    - audience
      - Enter the expected content for the 'audience' (aud) claim in the JWT
  - algorithm
    - Set the algorithm to be used for signing the JWT
  - key
    - Enter the key to be used for signing the JWT
- scopes
  - Enter the scopes to be requested
- login
  - Describe information for user authentication
  - auth_info
    - Enter the value in JSON format to be sent in the POST request for user authentication in this field
  - login_endpoint
    - Enter the URL of the endpoint for user authentication
    - If this item is present, log in with the API and use the session information held in the cookie for authorization requests

#### client credentials grant

For 'key', it is the same as with the `authorization code grant`, so please refer to that section for guidance.

```yaml
name-of-something:
  grant_type: 'client_credentials'
  client_id: <client_id>
  redirect_uri: <redirect_uri>
  token_endpoint: <token_endpoint>
  jwt_claims:
    audience: <audience>
  algorithm: 'RS256'
  key: '{"key": "value"}'
  scopes:
    - "user.read"
    - "user.write"
```

For each, set the following:

- grant_type
  - Set to `client_credentials`
- client_id
  - Enter the client ID issued by the authorization server
- client_secret
  - Enter the client secret issued by the authorization server
  - If this item is present, treat it as `client_secret_post` as the client authentication method
- redirect_uri
  - Enter the redirect URI registered with the authorization server
- token_endpoint
  - Enter the URL of the token endpoint
- private_key_jwt
  - Enter following items if you want to use the `private_key_jwt` format
  - jwt_claims
    - Set only 'audience' (aud) claim
    - To use the 'private_key_jwt' format for requesting an access token
    - audience
      - Enter the expected content for the 'audience' (aud) claim in the JWT
  - algorithm
    - Set the algorithm to be used for signing the JWT
  - key
    - Enter the key to be used for signing the JWT
- scopes
  - Enter the scopes to be requested

### Run command with options

This tool allows you to specify the following three options.

- `-f`
  - Specify the config file to be used
  - By default, the tool expects a file named 'config.yml'
- `-c`
  - Specify the key to be used from the config file
  - By default, the tool expects a key named `local`
- `--raw`
  - Using this option will output only the obtained access token
- `--version`
  - Display the version of this tool
