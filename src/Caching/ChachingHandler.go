package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// UserHandler provides HTTP handlers for user-related requests.
type UserHandler struct {
	service *UserService
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(service *UserService) *UserHandler {
	return &UserHandler{service}
}

// AuthHandler handles user authentication requests.
func (h *UserHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserPin  int    `json:"user_pin"`
		Password string `json:"password"`
	}

	// Decode the request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid request payload",
		})
		return
	}

	// Authenticate the user using the service
	user, err := h.service.Authenticate(req.UserPin, req.Password)
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

	// If authentication is successful, return the URL in JSON format
	url := fmt.Sprintf("http://192.168.0.106:8448/apigtw/v1/auth/accID=%d&pinID=%s", req.UserPin, req.Password)
	respondWithJSON(w, http.StatusOK, map[string]string{
		"url": url,
	})
}

// Helper function to write JSON response
func respondWithJSON(w http.ResponseWriter, status int, resp interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
