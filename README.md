# Simple API Gateway

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
  
  # The auth setting allows the user to provide a custom authentication sercice
  # to the gateway. The Gateway requires an `isAuth/` route which, if valid 
  # authentication is provided, returns the user ID
  auth: 
    path: /auth
    target: http://[SOME_AUTH_SERVICE]
  
  
  # Here you list all the backend services that sit behind the gateway. These 
  # can be services that don't require authentication in the `non-authenticated`
  # list or services that require authentication in the `authenticated` list.
  # For each service you specify the path/route URI and the target backend 
  # service
  services:
    non-authenticated:
      - path: /hello-world
        target: http://hello-world:8000
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


## Authentication

One of the main complexities of microservice backend development is 
authentication. This API Gateway is designed to work with any authenticaton services (auth services might be tied to application logic e.g. user auth vs iot auth...). In addition, decoupling the auth from the API gateway makes the gateway mostly statless (other than the configuration). 

The authentication mechanism here is to build your own authentication service and register it with the API gateway. As long as the isAuth route is provided the authenticateion mechanism of the gateway will work and the id of the authenticated user will be present in the header of backend services as `auth_id`.

Obviously having the gateway query another service for every service requiring authentication may add latency so there could be an option to verify valid IDs from a redis cache in future.