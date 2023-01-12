package main

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

// Get env variables and make available to the package
var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))
var redisHost = os.Getenv("REDIS_HOST")
var redisPort = os.Getenv("REDIS_PORT")
var redisPassword = os.Getenv("REDIS_PASSWORD")

// Package level variables
var gatewayConfig *GatewayConfig
var proxies *Proxies  // Holds the proxies for the non-authenticated and authenticated services
var rdb *redis.Client // Redis client
var rdbContext = context.Background()

// GatewayConfig is the top level struct for the gateway configuration
type GatewayConfig struct {
	ListenAddr string   `mapstructure:"listenAddr"`
	Cors       Cors     `mapstructure:"cors"`
	Services   Services `mapstructure:"services"`
}

type Cors struct {
	AllowedOrigins     []string `mapstructure:"allowedOrigins"`
	AllowedMethods     []string `mapstructure:"allowedMethods"`
	AllowedHeaders     []string `mapstructure:"allowedHeaders"`
	AllowedCredentials bool     `mapstructure:"allowedCredentials"`
	MaxAge             int      `mapstructure:"maxAge"`
}

// Services holds the array of non-authenticated and authenticated services
type Services struct {
	NonAuthenticated []Service `mapstructure:"non-authenticated" `
	Authenticated    []Service `mapstructure:"authenticated"`
}

// Service defines what a service looks like to the gateway. The name can be useful for logging purposes but at a
// minimum the route and target are required.
type Service struct {
	Name   string `mapstructure:"name"`
	Route  string `mapstructure:"route"`
	Target string `mapstructure:"target"`
}

// Proxies is similar to the Services struct but holds the actual proxies instead of the service definitions
type Proxies struct {
	nonAuthenticated []*httputil.ReverseProxy
	authenticated    []*httputil.ReverseProxy
}

func main() {
	// Read the gateway configuration file
	viper.AddConfigPath(".")            // Viper looks here for the files.
	viper.SetConfigType("yaml")         // Sets the format of the config file.
	viper.SetConfigName("gateway.conf") // Viper loads gateway.config.yaml
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Warning could not load configuration: %v", err)
	}
	viper.AutomaticEnv() // Merges any overrides set through env vars

	gatewayConfig = &GatewayConfig{}
	err = viper.UnmarshalKey("gateway", gatewayConfig)
	if err != nil {
		log.Fatalf("Warning could not read configuration: %v", err)
	}

	// Create the Redis client
	rdb = redis.NewClient(&redis.Options{
		Addr:     redisHost + ":" + redisPort,
		Password: redisPassword,
		DB:       0, // use default DB
	})

	// Exponential backoff retry for Redis connection
	for {
		wait := time.Duration(2)
		_, err = rdb.Ping(rdbContext).Result()
		if err != nil {
			log.Println("Warning could not connect to Redis: ", err, "\r\nRetrying...")
			time.Sleep(wait * time.Second)
			wait = wait * 2
		}
		break
	}

	// Start the user deletion listener (non-blocking)
	go listenForUserDeletion()

	log.Println("Initializing routes...")

	r := mux.NewRouter()

	// Add CORS middleware to mux router if user has configured CORS
	if len(gatewayConfig.Cors.AllowedOrigins) > 0 {
		log.Println("Enabling CORS...")
		r.Use(appendCors)
	}

	proxies = &Proxies{}

	// Register non-protected routes
	for _, service := range gatewayConfig.Services.NonAuthenticated {
		// Returns a proxy for the target url
		serviceProxy, err := newProxy(service.Target)
		if err != nil {
			log.Fatalf("Warning could not create proxy for service %s: %v", service.Name, err)
		}

		// Append the proxy to the list of non-authenticated proxies
		proxies.nonAuthenticated = append(proxies.nonAuthenticated, serviceProxy)

		log.Printf("Mapping '%v' service from %v ---> %v", service.Name, service.Route, service.Target)

		// Maps the HandlerFunc fn returned by NewHandler() fn that delegates the requests to the proxy
		r.HandleFunc(service.Route+"/{servicePath:.*}", newNonProtectedHandler(serviceProxy))
	}

	// Register protected routes
	for _, service := range gatewayConfig.Services.Authenticated {
		// Returns a proxy for the target url
		serviceProxy, err := newProxy(service.Target)
		if err != nil {
			log.Fatalf("Warning could not create proxy for service %s: %v", service.Name, err)
		}

		// Append the proxy to the list of authenticated proxies
		proxies.authenticated = append(proxies.authenticated, serviceProxy)

		log.Printf("Mapping '%v' service from %v ---> %v", service.Name, service.Route, service.Target)

		// Maps the HandlerFunc fn returned by NewHandler() fn that delegates the requests to the proxy
		r.HandleFunc(service.Route+"/{servicePath:.*}", newProtectedHandler(serviceProxy))
	}

	// Register the default '/isAuth' route which checks if the request of a user is authenticated
	r.HandleFunc("/isAuth", isAuth)

	log.Printf("Starting server on %v...", gatewayConfig.ListenAddr)
	err = http.ListenAndServe(gatewayConfig.ListenAddr, r)
	if err != nil {
		log.Fatalln("Fatal error could not start server: ", err)
	}
}

// TODO: Implement /isAlive healthcheck endpoint to provide warning if service is unavailable
// newProxy returns a proxy to the service based on the provided service target URL. If the target URL is not valid, an
// error is returned.
func newProxy(targetUrl string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(targetUrl)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	// BUG: Don't know what this does? I think it is what returns the request response every time there's a request?
	proxy.ModifyResponse = func(response *http.Response) error {
		dumpResponse, err := httputil.DumpResponse(response, false)
		if err != nil {
			return err
		}
		log.Println("Response: \r\n", string(dumpResponse))
		return nil
	}
	return proxy, nil
}

// newNonProtectedHandler returns a HandlerFunc that delegates the request to the proxy. The proxy is chosen based on
// the service path.
func newNonProtectedHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = mux.Vars(r)["servicePath"]
		log.Println("Request URL: ", r.URL.String())
		p.ServeHTTP(w, r)
	}
}

// newProtectedHandler returns a HandlerFunc that delegates the request to the proxy. The proxy is chosen based on the
// service path. The request is authenticated before being delegated to the proxy.
func newProtectedHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = mux.Vars(r)["servicePath"]
		log.Println("Request URL: ", r.URL.String())
		// Check if request is authenticated
		status, body := authenticate(r)
		switch status {
		case 200:
			// Request is authenticated
			// Append the authentication ID to the header of the request to be sent proxied to the service
			r.Header.Set("auth_id", body)
			p.ServeHTTP(w, r)
		default:
			// Else, some error occurred and unable to authenticate request. Return the response code and error message.
			w.WriteHeader(status)
			_, err := w.Write([]byte(body))
			if err != nil {
				log.Println("Warning could not write response: ", err)
			}
		}
	}
}

// appendCors append the CORS headers to response. This is a middleware registered to the mux router.
func appendCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Set headers
		w.Header().Set("Access-Control-Allow-Origin", confCorsListToString(gatewayConfig.Cors.AllowedOrigins))
		w.Header().Set("Access-Control-Allow-Methods", confCorsListToString(gatewayConfig.Cors.AllowedMethods))
		w.Header().Set("Access-Control-Allow-Headers", confCorsListToString(gatewayConfig.Cors.AllowedHeaders))
		w.Header().Set("Access-Control-Allow-Credentials", strconv.FormatBool(gatewayConfig.Cors.AllowedCredentials))
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(gatewayConfig.Cors.MaxAge))

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Next
		next.ServeHTTP(w, r)
	})
}
