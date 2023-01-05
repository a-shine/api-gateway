# Simple API Gateway with JWT authentication

![Alt text](https://raw.githubusercontent.com/a-shine/api-gateway/main/gateway-arch.drawio.svg)

## Introducing API Gateways

An API gateway is a reverse proxy server which itself is a type of proxy server
that typically sits behind the firewall in a private network and directs client
requests to the appropriate backend server.

The API gateway provides a single endpoint to whom API calls can be addressed
in multiservice architectures (e.g. microservices) and then forwards that
request to the appropriate service.

While it simplifies API calls for client by providing a single host it also
introduces a single point of failure (even if replicated) so it is important
that it is robust and well provisioned.

In addition to simply routing requests, an API gateway can have extra features
such as authentication (knowing who somebody is), authorization (knowing if
they're allowed) and monitoring API activity.

## Getting started

### Configuring the API Gateway

Start by creating an API configuration file and name it `gateway.conf.yaml`.
Bellow is a sample Gateway configuration:

```yaml
gateway:

  # Specify the Gatway listneing address for example `localhost:8000`
  listenAddr: :8000

  # Here you list all the backend services that sit behind the gateway. These 
  # can be services that don't require authentication in the `non-authenticated`
  # list or services that require authentication in the `authenticated` list.
  # For each service you specify the path/route URI and the target backend 
  # service
  services:
    non-authenticated:
      - path: /auth
        target: http://user-management:8000
    # All protected services have the user ID appended to the header before 
    # being routed to the service
    authenticated:
      - path: /hello-user
        target: http://hello-user:8000
```

In authenticated services, the Gateway appends the authenticated requester's ID
to the header (that's where the `isAuth/` is necessary) and proceeds to forward
the request to desired backend service.

### Running the API Gateway

#### Locally on machine

1. Clone repository
2. With Go installed on machine, install dependencies `go mod init `
3. Build the binary with `go build main.go`
4. Run the binary with ./main`

#### Container image (recommended)

The gateway is used for local development and can be used in a local container
orchestration tool such as Docker Compose or MiniKub.

1. Pull the docker image from the repository/create gateway service in Docker Compose
2. In docker compose

```yaml
compose:
services:
  api-gateway:
    image: ashinebourne/api-gateway:latest
    ports:
      - "8000:8000"
    volumes:
      - gateway.conf.yaml:/
```

## Authentication and authorisation

One of the main complexities of microservice backend development is
authentication. This API Gateway is designed to work with any authenticaton services (auth services might be tied to
application logic e.g. user auth vs iot auth...). In addition, decoupling the auth from the API gateway makes the
gateway mostly statless (other than the configuration).

The authentication mechanism here is to build your own authentication service and register it with the API gateway. As
long as the isAuth route is provided the authenticateion mechanism of the gateway will work and the id of the
authenticated user will be present in the header of backend services as `auth_id`.

Obviously having the gateway query another service for every service requiring authentication may add latency so there
could be an option to verify valid IDs from a redis cache in future.

If you want a plug and play user authentication service you can use the a-shine/user-auth service

Because the authentication/authorisation service is required to verify if a request is authenticated and authrosied it
is also a single point of failure

Just verify JWT token locally and check if they are in the auth-blacklist. The authentication management service can
post blacklisted IDs into the cache (it creates tighter coupling but allows immediate removal of unauthorised users)

looks for JWT token in cookies

JWT payload
Id
jwt.RegisteredClaims