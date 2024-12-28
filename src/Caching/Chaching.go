package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

// Struct to store JSON response
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// MySQL connection string
const (
	dbUser     = "root"       // Your MySQL username
	dbPassword = "password"   // Your MySQL password
	dbName     = "cashpay_db" // Database name
)

func main() {
	// Set up route
	http.HandleFunc("/snrcoin/apigtw/v1/auth", authHandler)

	// Start server on port 8448
	log.Println("Starting server on port 8448...")
	log.Fatal(http.ListenAndServe(":8448", nil))
}

// Function to handle authentication
func authHandler(w http.ResponseWriter, r *http.Request) {
	// Parse URL query parameters
	query := r.URL.Query()
	userID := query.Get("userID")
	password := query.Get("pass")

	if userID == "" || password == "" {
		// Missing parameters, return error
		respondWithJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Missing userID or password",
		})
		return
	}

	// Connect to MySQL database
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@/%s", dbUser, dbPassword, dbName))
	if err != nil {
		log.Fatal(err)
		respondWithJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to connect to the database",
		})
		return
	}
	defer db.Close()

	// Check if user exists in the app_users table
	var storedPassword string
	queryStr := "SELECT password FROM app_users WHERE username = ?"
	err = db.QueryRow(queryStr, userID).Scan(&storedPassword)

	if err != nil {
		if err == sql.ErrNoRows {
			// User not found
			respondWithJSON(w, http.StatusUnauthorized, Response{
				Success: false,
				Message: "Invalid username or password",
			})
		} else {
			// Other error
			log.Println(err)
			respondWithJSON(w, http.StatusInternalServerError, Response{
				Success: false,
				Message: "Database error",
			})
		}
		return
	}

	// Compare the stored password with the one provided
	if password != storedPassword {
		respondWithJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Message: "Invalid username or password",
		})
		return
	}

	// If credentials match, return success
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Login successful",
	})
}

// Helper function to write JSON response
func respondWithJSON(w http.ResponseWriter, status int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
