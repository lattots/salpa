# Salpa

## Motivation

Salpa makes implementing OAuth2 based authentication simple and convenient. It does this by implementing an authentication microservice, your client application can call to create JWT's for the user. With Salpa, you never have to deal with setting up OAuth2 or manually signing access tokens. You spin up a Salpa container and send user there to authenticate.

## Installation

### Server

Salpa server is built with [Docker](https://docs.docker.com/engine/install/) so naturally this needs to be installed on the host machine.

### Client application

Salpa currently has a Go client library implementation that can be used in client applications:

```bash
go get github.com/lattots/salpa
```

## Usage

### Setting up Salpa server

#### OAuth2 provider

In order to use an OAuth2 provider, you usually need to create a client in the providers web console. For Google you can create the client [here](https://console.cloud.google.com/auth/clients). Make sure to also save the client ID and secret given to you by your OAuth2 provider. We'll be needing them later.

#### Server setup

To start using Salpa you first need to create a configuration file. You can use `config/template.yaml` as a reference to make sure your configuration follows the expected format. This is an example configuration for a simple Google only Salpa instance:

```yaml
providers:
  google:
    active: true
    env:
      clientID: "GOOGLE_CLIENT_ID"
      clientSecret: "GOOGLE_CLIENT_SECRET"

store:
  driver: "sqlite"
  connectionString: "/app/data/token.db"

service:
  # You can create your own ED25519 key file or let Salpa create the key for you
  privateKeyFilename: "/app/data/private_key"

  port: 5875 # This is the default port of Salpa server

  serviceDomain: "https://this.com" # Domain of the Salpa server

  appDomain: "https://client.application.com" # Domain of the client application
```

Note that if you want to provide your own access token signing key, you need to create it yourself with OpenSSH:

```bash
ssh-keygen -t ed25519 -f ./data/private_key
```

Deploying Salpa is most convenient using Docker Compose. You can spin up the Salpa server with the following Compose declaration:

```yaml
services:
  salpa:
    image: lattots/salpa:latest

    environment:
      # The server will look for the configuration file here
      SALPA_CONF_FILENAME: "/app/data/salpa_config.yaml"

    volumes:
      # Remember to mount the directory containing the configuration and private key files
      - ./data/:/app/data

    secrets:
      # Secrets vary depending on the OAuth2 providers being used
      - google_client_id
      - google_client_secret

    entrypoint: >
      sh -c "
        # Remember to export the secrets as environment variables
        # The names must match the names provided in the configuration file
        export GOOGLE_CLIENT_ID=$$(cat /run/secrets/google_client_id);
        export GOOGLE_CLIENT_SECRET=$$(cat /run/secrets/google_client_secret);

        exec salpa-server
      "
```

Now your Salpa server should be running and be ready to accept requests from your client applications.

### Calling the auth service

To authenticate API requests using Salpa you can use the provided client Go library. It implements a middleware function that can verify access tokens and authorize API calls based on parameters of your liking.

In order to authorize API calls the client application must implement a simple Authorizer interface. This would in a real world setting be a user database of some sort, however here we can mock it by using a hash map:

```go
type authorizer struct {
	userAttributes map[string]map[string]string // map email->attributes
}

func (a *authorizer) GetLevel(email string) (string, error) {
	return a.GetAttribute("level", email)
}

func (a *authorizer) GetAttribute(attributeName, email string) (string, error) {
	usrAttr := a.userAttributes[email]
	if usrAttr == nil {
		return "", errors.New("user not found")
	}
	attr := usrAttr[attributeName]
	if attr == "" {
		return "", errors.New("attribute not found")
	}
	return attr, nil
}
```

To use the authentication middleware you must first create an instance of auth service:

```go
import (
    "github.com/lattots/salpa/public/client"
    "github.com/lattots/salpa/public/service"
)

authorizer := &authorizer{
    userAttributes: make(map[string]map[string]string),
}

// Populate authorizer with some test data
authorizer.userAttributes["john.doe@gmail.com"] = map[string]string{
    "level":  "admin",
    "userID": "123",
}

// Use local auth service (running in Docker network)
authClient := client.NewHTTPClient("http://salpa:5875", []string{"google"})

authService := service.NewDefaultService(authorizer, authClient)
```

Now that you have access to the auth service, you can call the provided middlewares like this:

```go
mux := http.NewServeMux()

mux.HandleFunc("GET /", handleRoot)
// AllowOnly restricts access to a certain "user level", in this case "admin"
// You can whatever levels you like (free tier, pro etc.)
mux.HandleFunc("GET /admin", authService.AllowOnly(handleAdmin, []string{"admin"}))
// AllowPathVal restricts access to users with the same attribute as in the query path
// This can be used to only allow users to query their own info
mux.HandleFunc("GET /user-pages/{userID}", authService.AllowPathVal(handleUserPage, "userID"))
```

If you simply want to access the User object from a HTTP request, you can use the Auth Client object to verify and parse the incoming access token:

```go
import "github.com/lattots/salpa/public/client"

type handler struct {
    authClient client.AuthClient
}

func (h *handler) FooHandler(w http.ResponseWriter, r *http.Request) {
    // Use the provided function to parse and verify incoming access token
    userClaims, err := client.GetClaims(h.authClient, r)
    // Handle error cases gracefully
    if errors.Is(err, client.ErrTokenNotFound) {
        http.Error(w, "user is not authenticated", http.StatusUnauthorized)
        return
    }
    if errors.Is(err, client.ErrInvalidToken) {
        http.Error(w, "access token is invalid", http.StatusUnauthorized)
        return
    }
    if err != nil {
        log.Printf("failed to get user claims: %s\n", err)
        http.Error(w, "internal server error", http.StatusInternalServerError)
        return
    }

    // Do something useful with the user information...
    log.Println("Verified user ID:", userClaims.UserID)
    log.Println("Verified user email:", userClaims.Email)
}
```
