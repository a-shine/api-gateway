package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

type Claims struct {
	Id string `json:"id"`
	jwt.RegisteredClaims
}

var AUTH_PROXY *httputil.ReverseProxy

type GatewayConfig struct {
	ListenAddr string `mapstructure:"listenAddr"`
	Routes     Routes `mapstructure:"services"`
}

type Routes struct {
	NonAuthenticated []ContextTarget `mapstructure:"non-authenticated"`
	Authenticated    []ContextTarget `mapstructure:"authenticated"`
}

type ContextTarget struct {
	Context string `mapstructure:"context"`
	Target  string `mapstructure:"target"`
}

var rdb *redis.Client

func main() {
	rdb = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_HOST") + ":" + os.Getenv("REDIS_PORT"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0, // use default DB
	})

	viper.AddConfigPath(".")            // Viper looks here for the files.
	viper.SetConfigType("yaml")         // Sets the format of the config file.
	viper.SetConfigName("gateway.conf") // Viper loads gateway.config.yaml
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

	// // Reserve auth route
	// authProxy, err := NewProxy(gatewayConfig.Auth.Target)
	// if err != nil {
	// 	panic(err)
	// }

	// Used to check if the request is authorised
	// AUTH_PROXY = authProxy

	// r.HandleFunc(gatewayConfig.Auth.Context+"/{authPath:.*}", NewNonProtectedHandler(authProxy))

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
// func isAuth(r *http.Request) (int, string) {
// 	// Cache original path before updating to isAuth path
// 	cachePath := r.URL.Path

// 	r.URL.Path = "/isAuth"

// 	w := httptest.NewRecorder() // record response writer

// 	AUTH_PROXY.ServeHTTP(w, r)

// 	r.URL.Path = cachePath // change back path to original before continuing with route handling

// 	return w.Code, w.Body.String()
// }

// TODO: Verify user ID is still active/valid by crosschecking with DB
func isAuth(r *http.Request) (int, string) {
	// We can obtain the session token from the requests cookies, which come with every request
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			// w.WriteHeader(http.StatusUnauthorized)
			return http.StatusUnauthorized, ""
		}
		// For any other type of error, return a bad request status
		return http.StatusBadRequest, ""
	}

	// Get the JWT string from the cookie
	tknStr := c.Value

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return os.Getenv("JWT_SECRET_KEY"), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return http.StatusUnauthorized, ""
		}
		return http.StatusBadRequest, ""
	}
	if !tkn.Valid {
		return http.StatusUnauthorized, ""
	}

	// Check if authenticated entity is active/valid (authorised)
	_, redErr := rdb.Get(context.Background(), claims.Id).Result()
	if redErr == redis.Nil {
		fmt.Println("key2 does not exist")
		// then has NOT been blacklisted
		// Finally, return the welcome message to the user, along with their
		// username given in the token
		return http.StatusOK, claims.Id
	} else if err != nil {
		return http.StatusInternalServerError, ""
	} else {
		return http.StatusUnauthorized, ""
	}
}
