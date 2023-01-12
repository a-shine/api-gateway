package main

import (
	"log"
	"net/http"
)

func isAuth(w http.ResponseWriter, r *http.Request) {
	status, body := authenticate(r)
	switch status {
	case 200:
		// r.Header.Set("auth_id", body) // append the user id to the header of the request to be sent to the services
		w.WriteHeader(http.StatusOK)
		return
	default:
		w.WriteHeader(status)
		_, err := w.Write([]byte(body))
		if err != nil {
			log.Println("Error writing response body for isAuth handler: ", err)
		}
		return
	}
}
