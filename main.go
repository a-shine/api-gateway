package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

var AUTH_PROXY *httputil.ReverseProxy

type GatewayConfig struct {
	ListenAddr string        `mapstructure:"listenAddr"`
	Auth       ContextTarget `mapstructure:"auth"`
	Routes     Routes        `mapstructure:"routes"`
}

type Routes struct {
	NonAuthenticated []ContextTarget `mapstructure:"non-authenticated"`
	Authenticated    []ContextTarget `mapstructure:"authenticated"`
}

type ContextTarget struct {
	Context string `mapstructure:"context"`
	Target  string `mapstructure:"target"`
}

func main() {
	viper.AddConfigPath(".")              // Viper looks here for the files.
	viper.SetConfigType("yaml")           // Sets the format of the config file.
	viper.SetConfigName("gateway.config") // Viper loads gateway.config.yaml
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Warning could not load configuration: %v", err)
	}
	viper.AutomaticEnv() // Merges any overrides set through env vars.

	gatewayConfig := &GatewayConfig{}

	err = viper.UnmarshalKey("gateway", gatewayConfig)
	if err != nil {
		panic(err)
	}

	fmt.Println(gatewayConfig)

	log.Println("Initializing routes...")

	r := mux.NewRouter()

	// Reserve auth route
	authProxy, err := NewProxy(gatewayConfig.Auth.Target)
	if err != nil {
		panic(err)
	}

	// Used to check if the request is authorised
	AUTH_PROXY = authProxy

	r.HandleFunc(gatewayConfig.Auth.Context+"/{authPath:.*}", NewNonProtectedHandler(authProxy))

	// Register non-protected routes
	for _, route := range gatewayConfig.Routes.NonAuthenticated {
		// Returns a proxy for the target url.
		serviceProxy, err := NewProxy(route.Target)
		if err != nil {
			panic(err)
		}
		// Just logging the mapping.
		log.Printf("Mapping %v ---> %v", route.Context, route.Target)
		// Maps the HandlerFunc fn returned by NewHandler() fn
		// that delegates the requests to the proxy.
		r.HandleFunc(route.Context+"/{servicePath:.*}", NewNonProtectedHandler(serviceProxy))
	}

	// Register protected routes
	for _, route := range gatewayConfig.Routes.Authenticated {
		// Returns a proxy for the target url.
		serviceProxy, err := NewProxy(route.Target)
		if err != nil {
			panic(err)
		}
		// Just logging the mapping.
		log.Printf("Mapping %v ---> %v", route.Context, route.Target)
		// Maps the HandlerFunc fn returned by NewHandler() fn
		// that delegates the requests to the proxy.
		r.HandleFunc(route.Context+"/{servicePath:.*}", NewProtectedHandler(serviceProxy))
	}

	log.Printf("Started server on %v", gatewayConfig.ListenAddr)
	http.ListenAndServe(gatewayConfig.ListenAddr, r)
}

func NewProxy(targetUrl string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(targetUrl)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
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

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

func NewNonProtectedHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		r.URL.Path = mux.Vars(r)["authPath"]
		log.Println("Request URL: ", r.URL.String())
		p.ServeHTTP(w, r)
	}
}

func NewProtectedHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		r.URL.Path = mux.Vars(r)["servicePath"]
		log.Println("Request URL: ", r.URL.String())
		// Check if auth - append user ID to header (add Id to claim/db logic)
		status, id := isAuth(r)
		switch status {
		case 200:
			r.Header.Set("auth_id", id) // append the user id to the header of the request to be sent to the services
			p.ServeHTTP(w, r)
		default:
			w.WriteHeader(status)
		}
	}
}

// isAuth queries the authentication service and checks if the request is authorised, if it is returns the requester's ID
// query the auth service
// make a call to the auth service
// if the request is authorised return the user id
func isAuth(r *http.Request) (int, string) {
	// Cache original path before updating to isAuth path
	cachePath := r.URL.Path

	r.URL.Path = "/isAuth"

	w := httptest.NewRecorder() // record response writer

	AUTH_PROXY.ServeHTTP(w, r)

	r.URL.Path = cachePath // change back path to original before continuing with route handling

	return w.Code, w.Body.String()
}
