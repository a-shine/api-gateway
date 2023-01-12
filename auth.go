package main

import (
	"context"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
)

type Claims struct {
	Id string `json:"id"`
	jwt.RegisteredClaims
}

// authenticate checks if the request has a valid JWT token cookie and checks if the user has not been blacklisted. If
// the cookies is missing/invalid, token incorrect/invalid or user has been blacklisted, the request is rejected with
// the appropriate status code and a JSON formatted error message are returned. Else a 200 (Status OK) code is returned
// with the user ID string.
func authenticate(r *http.Request) (int, string) {
	// We can obtain the token from the requests cookies, which come with every request
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			return http.StatusUnauthorized, `{"message":"No token cookie"}`
		}
		// For any other type of error, return a bad request status
		return http.StatusBadRequest, `{"message":"Unable to get token cookie"}`
	}

	// Get the JWT string from the cookie
	tknStr := c.Value

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT string into
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return http.StatusUnauthorized, `{"message":"Invalid token signature"}`
		}
		return http.StatusBadRequest, `{"message":"Unable to parse token"}`
	}
	if !tkn.Valid {
		return http.StatusUnauthorized, `{"message":"Invalid or expired token"}`
	}

	// Check if authenticated entity is active/valid (authorised)
	_, redErr := rdb.Get(context.Background(), claims.Id).Result()
	if redErr != nil {
		if redErr == redis.Nil {
			// then has NOT been blacklisted
			// Finally, return the welcome message to the user, along with their
			// username given in the token
			return http.StatusOK, claims.Id
		}
		return http.StatusInternalServerError, `{"message":"Failed to check user authorisation"}`
	} else {
		return http.StatusUnauthorized, `{"message":"User has been suspended"}`
	}
}
