package main

import (
	"github.com/go-redis/redis/v8"
	"log"
	"net/http"
	"net/http/httptest"
)

// listenForUserDeletion listens for user deletion messages published to the Redis 'user-delete' topic. When receiving
// a user deletion request, each authenticated service is called and asked to delete user data. Each authenticated
// services is required to implement and '/user-delete' endpoint and responsible for handling graceful user deletion.
// The message payload must be the ID of the user to delete.
func listenForUserDeletion() {
	// There is no error because go-redis automatically reconnects on error
	pubsub := rdb.Subscribe(rdbContext, "user-delete")

	// Close the subscription when done
	defer func(pubsub *redis.PubSub) {
		err := pubsub.Close()
		if err != nil {
			log.Println("Error closing Redis subscription: ", err)
		}
	}(pubsub)

	// Go channel which receives messages
	ch := pubsub.Channel()

	// Listen for user delete request on user-delete pubsub channel
	for msg := range ch {
		// log.Printf(msg.Channel, msg.Payload)
		// Make call to each authenticated service to delete the user data
		for _, service := range proxies.authenticated {
			req, _ := http.NewRequest("DELETE", "/user-delete", nil)

			// Assume the user ID is the message payload
			req.Header.Set("id", msg.Payload)

			// http response writer
			w := httptest.NewRecorder()

			service.ServeHTTP(w, req)

			// TODO: Handle a failed user deletion
			log.Printf("Response: %v", w.Result())
		}
	}
}
