package authentication

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// AuthenticationHandler handles user-related requests.
type AuthenticationHandler struct {
	Manager *AuthManager
}

type AuthHandler struct {
	// Define necessary fields here, like a manager for handling auth logic
	Manager *AuthManager
}

// NewUserHandler creates a new AuthenticationHandler with the provided AuthManager.
func NewUserHandler(handler *AuthHandler) *AuthenticationHandler {
	return &AuthenticationHandler{
		Manager: handler.Manager, // Correctly assign the Manager field
	}
}

// enableCors adds the necessary CORS headers to the response
func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")                                              // Allow all origins (can specify a domain instead of "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")               // Allowed HTTP methods
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, Authorization") // Allowed headers
}

// AuthHandler handles user authentication requests.
/*
func (h *AuthenticationHandler) Login(w http.ResponseWriter, r *http.Request) {

	enableCors(&w) // Enable CORS for all incoming requests

	// Read and log the raw request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Unable to read request body",
		})
		return
	}
	// Log the raw request body for debugging
	fmt.Println("Raw Request Body:", string(bodyBytes))

	// Reset the body for further processing
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Decode the request body into the struct
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid request payload",
		})
		return
	}

	fmt.Printf("Parsed Request Data: %+v\n", req)
	// Validate the provided API key using the AuthManager
	isValid, err := h.Manager.ValidateAPIKey(req.APIKey)
	if err != nil || !isValid {
		respondWithJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Message: "Invalid or expired API key",
		})
		return
	}

	// Validate the token (if token validation is part of the login process)
	if req.Token != "" {
		isValidToken, err := h.Manager.ValidateTokenManager(req.Token)
		if err != nil || !isValidToken {
			respondWithJSON(w, http.StatusUnauthorized, Response{
				Success: false,
				Message: "Invalid or expired token",
			})
			return
		} else {
			respondWithJSON(w, http.StatusUnauthorized, Response{
				Success: false,
				Message: "Token Error",
			})
		}
	} else {
		respondWithJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Message: "Token is not comming!",
		})
	}

	// Variable to hold the authenticated user
	var user *rWeb

	// Authenticate based on LoginModeType
	switch req.LoginModeType {
	case "web":
		user, err = h.Manager.LoginManagerWeb(req.LoginModeType, req.UserName, req.UserPassword, req.APIKey)
	case "desktop":
		user, err = h.Manager.LoginManagerDesktop(req.LoginModeType, req.UserName, req.UserPassword, req.APIKey)
	case "tv":
		user, err = h.Manager.LoginManagerTV(req.LoginModeType, req.UserName, req.UserPassword, req.APIKey)
	case "iot":
		user, err = h.Manager.LoginManagerIOT(req.LoginModeType, req.UserPhone, req.UserPin, req.APIKey)
	default:
		respondWithJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid LoginModeType",
		})
		return
	}

	// Handle potential errors during authentication
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Error during authentication: " + err.Error(),
		})
		return
	}

	// If the user is not authenticated
	if user == nil {
		respondWithJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Message: "Invalid user credentials",
		})
		return
	}

	addrID, _ := strconv.ParseInt(*user.AddrID, 10, 64) // Convert AddrID to int64
	// Prepare session data dynamically based on LoginModeType
	sessionData := SessionData{
		ParentID:      int64(user.ParentID),
		OrgID:         int64(user.OrgID),
		AddrID:        addrID,                                    // Dereference pointer if needed
		AccountNumber: strconv.FormatInt(user.AccountNumber, 15), // Convert int64 to string
		DistributorID: int64(user.DistributorID),
		Key:           "ApiKey",
		Value:         *user.APIAuthKey,
	}

	switch req.LoginModeType {
	case "web":
		sessionData.EmailAddress = *user.EmailAddress
		sessionData.SystemName = *user.SystemName

	case "desktop":
		sessionData.EmailAddress = *user.EmailAddress
		sessionData.SystemName = *user.SystemName
	case "mobile":
		sessionData.UserPhone = user.PhoneNo
		sessionData.Key = "MobileSessionKey"
		sessionData.Value = "MobileSessionValue"
	case "tv":
		sessionData.SystemName = *user.SystemName
		sessionData.Key = "ApiKey"
		sessionData.Value = *user.APIAuthKey
	case "iot":
		sessionData.SystemName = *user.SystemName
		sessionData.Key = "ApiKey"
		sessionData.Value = *user.APIAuthKey
	}

	// Create a new session
	session, err := h.Manager.CreateSessionManager(int64(user.ID), *user.SystemName, sessionData)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to create session",
		})
		return
	}

	// Return the session token in JSON format
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"session_token": session.SessionToken,
		"expires_at":    session.ExpiresAt,
		"ses_key":       sessionData.Key,
		"ses_val":       sessionData.Value,
	})
}
*/
func (h *AuthenticationHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// Parse and validate parameters
	//rawURL := r.URL.String()
	//loginModeType := "web" // Assuming the login mode is always "web"
	uName := r.URL.Query().Get("UserName")
	uPassword := r.URL.Query().Get("user_password")
	//apiKey := r.URL.Query().Get("api_key")

	if uName == "" || uPassword == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Log the request details for debugging purposes
	//fmt.Printf("Received login request: rawURL=%s, UserName=%s, APIKey=%s\n", rawURL, uName, apiKey)

	// Call manager function
	rtnData, err := h.Manager.LoginManagerWeb(uName, uPassword)
	if err != nil {
		http.Error(w, fmt.Sprintf("Login failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Respond with success
	response := Response{
		Success: true,
		Message: "Login successful",
		Data:    rtnData, // Ensure this matches the expected return type
	}
	respondWithJSON(w, http.StatusOK, response)
}

// TokenAuthenticationHandler handles token-based authentication.
func (h *AuthHandler) TokenAuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization token missing", http.StatusUnauthorized)
		return
	}

	isValid, err := h.Manager.ValidateTokenManager(token)
	if err != nil || !isValid {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Token is valid"))
}

// APIKeyHandler handles API key verification.
func (h *AuthHandler) APIKeyHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		http.Error(w, "API key missing", http.StatusUnauthorized)
		return
	}

	isValid, err := h.Manager.ValidateAPIKey(apiKey)
	if err != nil || !isValid {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("API key is valid"))
}

// OAuthHandler handles OAuth2.0 authentication requests.
func (h *AuthHandler) OAuthHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	code := r.URL.Query().Get("code")

	if clientID == "" || code == "" {
		http.Error(w, "Missing client_id or code", http.StatusBadRequest)
		return
	}

	token, err := h.Manager.GenerateOAuthToken(clientID, code)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"access_token": token})
}

// respondWithJSON writes a JSON response to the client.
func respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	// Set CORS headers here
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost") // Set origin to match frontend
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Set Content-Type for JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// Encode the payload to JSON and send it to the client
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Println("Error encoding response:", err)
	}
}
