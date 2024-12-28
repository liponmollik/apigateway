package main

import (
	"fmt"
	"log"
	"net/http"
	"src/Authentication/AuthenticationHandler"
	"src/Authentication/AuthenticationManager"
	"src/Authentication/AuthenticationRepository"

	"github.com/gorilla/mux"
)

func main() {
	// Initialize repository, manager, and handler
	repo := &AuthenticationRepository.UserRepository{}
	manager := &AuthenticationManager.Manager{Repo: repo}
	handler := &AuthenticationHandler.Handler{Manager: manager}

	// Initialize the router
	router := mux.NewRouter()

	// Set up routes
	router.HandleFunc("/auth/login", handler.Authenticate).Methods("POST")

	// Start the server
	fmt.Println("Starting API Gateway on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
