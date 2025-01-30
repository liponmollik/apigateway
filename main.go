package main

import (
	"apigateway/config"
	"apigateway/src/audittrail"
	"apigateway/src/authentication"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {

	// Connect to Redis and MySQL using the loaded config
	client, err := config.ConnectRedis()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer client.Close()

	err = config.ConnectMySQL()
	if err != nil {
		log.Fatalf("Failed to connect to MySQL: %v", err)
	}
	// Initialize repository and manager
	repo := &audittrail.AuditTrailRepository{DB: config.GetMySQLDB()}
	manager := &audittrail.AuditTrailManager{Repo: repo}
	handler := &audittrail.AuditTrailHandler{Manager: manager}

	// Initialize Authentication Dependencies
	authRepo := &authentication.AuthRepository{DB: config.GetMySQLDB()}
	authManager := &authentication.AuthManager{Repo: authRepo}
	authHandler := &authentication.AuthenticationHandler{Manager: authManager}

	router := mux.NewRouter()

	//Authentication Management
	//Web
	//router.HandleFunc("/api/v1/web/auth/login", authHandler.Login).Methods("GET")
	router.HandleFunc("/api/v1/web/auth/loginweb", authHandler.LoginHandler).Methods("POST")
	//router.HandleFunc("/users/{id}", userHandler).Methods("GET")
	//router.HandleFunc("/api/v1/web/auth/login/success", authHandler.ListSuspectedUsersHandler).Methods("GET")
	//router.HandleFunc("/api/v1/web/auth/login/failure", authHandler.HandleFailedLoginsByDate).Methods("GET")
	//router.HandleFunc("/api/v1/web/dashboard", authHandler.GetUserLeaderboardHandler).Methods("GET")
	//Mobile
	//router.HandleFunc("/api/v1/mob/auth/login", authHandler.GetAllAuditTrailsHandler).Methods("GET")
	//router.HandleFunc("/api/v1/mob/auth/login/success", authHandler.ListSuspectedUsersHandler).Methods("GET")
	//router.HandleFunc("/api/v1/mob/auth/login/failure", authHandler.HandleFailedLoginsByDate).Methods("GET")
	//router.HandleFunc("/api/v1/mob/dashboard", authHandler.GetUserLeaderboardHandler).Methods("GET")
	//Desktop
	//router.HandleFunc("/api/v1/desk/auth/login", authHandler.GetAllAuditTrailsHandler).Methods("GET")
	//router.HandleFunc("/api/v1/desk/auth/login/success", authHandler.ListSuspectedUsersHandler).Methods("GET")
	//router.HandleFunc("/api/v1/desk/auth/login/failure", authHandler.HandleFailedLoginsByDate).Methods("GET")
	//router.HandleFunc("/api/v1/desk/dashboard", authHandler.GetUserLeaderboardHandler).Methods("GET")
	//IoT
	//router.HandleFunc("/api/v1/iot/auth/login", authHandler.GetAllAuditTrailsHandler).Methods("GET")
	//router.HandleFunc("/api/v1/iot/auth/login/success", authHandler.ListSuspectedUsersHandler).Methods("GET")
	//router.HandleFunc("/api/v1/iot/auth/login/failure", authHandler.HandleFailedLoginsByDate).Methods("GET")
	//router.HandleFunc("/api/v1/iot/dashboard", authHandler.GetUserLeaderboardHandler).Methods("GET")

	// Audit Trail HTTP routes
	router.HandleFunc("/api/v1/web/users/audittrails/loginrecords/list", handler.GetAllAuditTrailsHandler).Methods("GET")
	router.HandleFunc("/api/v1/web/users/audittrails/loginrecords/suspected", handler.ListSuspectedUsersHandler).Methods("GET")
	router.HandleFunc("/api/v1/web/users/audittrails/loginrecords/failedlogins", handler.HandleFailedLoginsByDate).Methods("GET")
	router.HandleFunc("/api/v1/web/users/audittrails/loginrecords/leaderboard", handler.GetUserLeaderboardHandler).Methods("GET")
	router.HandleFunc("/api/v1/web/users/audittrails/loginrecords/longestsessions", handler.LongestSessions).Methods("GET")
	router.HandleFunc("/api/v1/web/users/audittrails/loginrecords/multipledevices", handler.MultipleDeviceLogins).Methods("GET")
	router.HandleFunc("/api/v1/web/users/audittrails/loginrecords/delete", handler.Delete).Methods("GET")
	router.HandleFunc("/api/v1/web/users/audittrails/loginrecords/view", handler.MultipleDeviceLogins).Methods("GET")

	// Start the server
	fmt.Println("Appsouls Server is running at http://localhost:8080/")

	log.Fatal(http.ListenAndServe(":8080", router))
}
