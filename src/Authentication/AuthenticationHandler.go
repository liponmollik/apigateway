package Authentication

import (
	"AuthenticationManager"
	"AuthenticationRepository"
	"AuthenticationModel"
	"encoding/json"
	"net/http"
)

// Response structure to send JSON responses
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    *User  `json:"data,omitempty"`
}

// UserHandler handles user-related requests.
type UserHandler struct {
	Manager *AuthenticationManager.Manager
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(service *UserService) *UserHandler {
	return &UserHandler{service: service}
}

// AuthHandler handles user authentication requests.
func (h *UserHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        UserAccount  int    `json:"user_account"`
        UserPin      int    `json:"user_pin"`
        UserPassword string `json:"password"`
        DeviceType   string `json:"dType"`  // "mobile" or "desktop"
    }

    // Decode the request body
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        respondWithJSON(w, http.StatusBadRequest, Response{
            Success: false,
            Message: "Invalid request payload",
        })
        return
    }

    // Variable to hold the authenticated user
    var user *AuthenticationManager.User
    var err error

    // Authenticate based on device type
    switch req.DeviceType {
    case "mobile":
        user, err = h.Manager.AuthenticateUserByDevice("mobile", fmt.Sprint(req.UserAccount), "", fmt.Sprint(req.UserPin))
    case "desktop":
        user, err = h.Manager.AuthenticateUserByDevice("desktop", fmt.Sprint(req.UserAccount), req.UserPassword, "")
    default:
        respondWithJSON(w, http.StatusBadRequest, Response{
            Success: false,
            Message: "Invalid device type",
        })
        return
    }

    // Handle potential errors during authentication
    if err != nil {
        respondWithJSON(w, http.StatusInternalServerError, Response{
            Success: false,
            Message: "Error during authentication",
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

    // If authentication is successful
    respondWithJSON(w, http.StatusOK, Response{
        Success: true,
        Message: "User authenticated successfully",
        Data:    user,
    })
}
	// Prepare session data
	sessionData := AuthenticationModel.SessionData{
		ParentID:      user.ParentID,
		OrgID:         user.OrgID,
		AddrID:        user.AddrID,
		AccountNumber: user.AccountNumber,
		DistributorID: user.DistributorID,
		EmailAddress:  user.EmailAddress,
		SystemName:    user.SystemName,
	}

	// Create a new session
	session, err := h.service.CreateSession(user.ID, req.UserPassword, sessionData)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to create session",
		})
		return
	}

	// If authentication is successful, return the session token in JSON format
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"session_token": session.SessionToken,
		"expires_at":    session.ExpiresAt,
	})
}

// AuthHandler provides HTTP handlers for authentication requests.
type AuthHandler struct {
	Manager *AuthenticationManager.AuthManager
}

// NewAuthHandler initializes a new AuthHandler.
func NewAuthHandler(manager *AuthenticationManager.AuthManager) *AuthHandler {
	return &AuthHandler{Manager: manager}
}

// TokenAuthenticationHandler handles token-based authentication.
func (h *AuthHandler) TokenAuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization token missing", http.StatusUnauthorized)
		return
	}

	isValid, err := h.Manager.ValidateToken(token)
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
func respondWithJSON(w http.ResponseWriter, status int, resp interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
