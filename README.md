# A very simple API Gateway with JWT authentication

![Simple API Gateway diagram](https://raw.githubusercontent.com/a-shine/api-gateway/main/api-gateway.drawio.svg)

## Introducing API Gateways

An API gateway is a reverse proxy server which is a type of proxy server that typically sits behind the firewall in a 
private network and directs client requests to the appropriate backend server.

The API gateway provides a single endpoint to whom API calls can be addressed in multiservice architectures (e.g.
microservices) and then forwards that request to the appropriate service.

While it simplifies API calls for client by providing a single host it also introduces a single point of failure (even
if replicated) so it is important that it is robust and well provisioned.

In addition to simply routing requests, an API gateway can have extra features such as authentication (knowing who
somebody is), authorization (knowing if they're allowed to access certain resources) and monitoring API activity.

## Features

This API gateway is designed to be very simple to use. It may not be the right choice for production (hasn't been 
thoroughly load tested) but can be used as an API gateway for development and testing. Other than the core role as a 
reverse proxy server, redirecting requests to the appropriate backend service, it also has the following features:

* Authentication 
  * Parse JWT tokens and append the authenticated ID to proxied requests (in the `auth_id` header) so that they are 
    available to the authenticated backend services
  * Verify if ID is authorised by checking a cache of blacklisted IDs (this enables realtime user suspension)
  * Cascade user data deletion for authenticated services by listing to the 'user-delete' channel
  * `/isAuth` route is provided by default, which returns an HTTP Status OK (200) if user is authenticated (can be used
    to check authentication status in a frontend application)
* User configurable CORS

## Getting started

### Dependencies

* The API gateway uses Redis for caching and pub/sub (used for user deletion cascade handling). It is recommended that 
you use Docker Compose locally to orchestrate the API gateway and Redis server.
* Each service is expected to provide an `/isAlive` endpoint
* Each authenticated service is expected to provide `/user-delete` endpoint and handle user deletion gracefully

### Configuring the API Gateway

Start by creating an API configuration file and name it `gateway.conf.yaml`.
Bellow is a sample Gateway configuration:

```yaml
gateway:

  # Specify the Gateway listening address for example `localhost:8000`
  listenAddr: :8000

  # Configure CORS (optional, omit if you do no need CORS)
  cors:
    allowedOrigins: ["*"]
    allowedMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowedHeaders: ["Origin", "Accept", "Content-Type", "X-Requested-With", "X-CSRF-Token"]
    allowedCredentials: true
    maxAge: 86400


  # Here you list all the backend services that sit behind the gateway. These can be services that don't require
  # authentication in the `non-authenticated` list or services that require authentication in the `authenticated` list.
  # For each service you specify the path/route URI and the target backend service.
  services:
    non-authenticated: # (optional, omit if you do not need non-authenticated services)
      - name: User management
        path: /user
        target: http://user-management:8000
    authenticated: # (optional, omit if you do not need authenticated services)
      # All protected/authenticated services have the user ID appended to the header before being routed to the service
      - name: Service A
        path: /service-a
        target: http://service-a:8000
```

In authenticated services, the Gateway appends the authenticated requester's ID to the header and proceeds to forward
the request to desired backend service.

### Running the API Gateway

#### Environment variables

The API gateway requires the following environment variables to be set:
* In order to connect to the Redis server
  * `REDIS_HOST`
  * `REDIS_PORT`
  * `REDIS_PASSWORD`
* A `JWT_SECRET_KEY` which is consistent with the application responsible for generating the JWT tokens. You can use 
  the [a-shine/user-auth](https://github.com/a-shine/user-auth) pre-made service to handle user management logic such 
  as user registration, login (generation of JWT tokens), logout, etc...

#### Locally on machine

1. Clone repository
2. With Go installed on machine, install dependencies `go mod init `
3. Build the binary with `go build main.go`
4. Run the binary with ./main` (remember that the env variables and Redis server must be configured)

#### Container image (recommended)

When using the Gateway, specially for local development it may be simpler to use a local container orchestration tool 
such as Docker Compose or MiniKub. This well help handle the orchestration of registered services, the required Redis 
server and environment variables.

A pre-built docker image is hosted at [ashinebourne/api-gateway](https://hub.docker.com/r/ashinebourne/api-gateway)

A sample Docker Compose configuration would look as such:

```yaml
services:
  api-gateway:
    image: ashinebourne/api-gateway:latest
    ports:
      - "8000:8000"
    environment:
      - REDIS_HOST=user-cache
      - REDIS_PORT=6379
      - REDIS_PASSWORD=password123
      - JWT_SECRET_KEY=secret
    volumes:
      - ./gateway.conf.yaml:/gateway.conf.yaml
  user-cache:
    image: redis
    ports:
      - 6379:6379
    command: /bin/sh -c "redis-server --requirepass $$REDIS_PASSWORD" # Required to get the PubSub functionality working
    environment:
      - REDIS_PASSWORD=password123
```

## A little more on authentication and authorisation

One of the main complexities of multiservice backend development is authentication. This API Gateway is designed to 
work with any authentication services (auth services might be tied to application logic e.g. user auth vs IOT device 
auth...). Decoupling the authentication and user management logic from the API gateway makes the gateway mostly 
stateless (other than the configuration and blacklist ID cache).

You can use any service you would like to manage users and generate JWT token as long as the JSON payload contains an 
`id`. The token must be stored as a Cookie with the name `token`. The ID of the authenticated user will be present in 
the header of backend services as `auth_id`.

If you want a plug-and-play user management abd authentication service which integrates with the PubSub Redis user 
deletion cascade strategy you can use the [a-shine/user-auth](https://github.com/a-shine/user-auth) service.