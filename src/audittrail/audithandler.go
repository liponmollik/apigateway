package audittrail

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

// AuditTrailHandler handles HTTP requests for audit trails
type AuditTrailHandler struct {
	Manager *AuditTrailManager
}

// RespondWithJSON is a helper function to respond with JSON
func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

func auditTrailHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received request for /audittrails/list")
	fmt.Fprintf(w, "List of audit trails")
}

// HomeHandler handles the root route
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Welcome to the home page!")
}

// ListAuditTrails handles the "List of audit trails" request
func (h *AuditTrailHandler) ListAuditTrails(w http.ResponseWriter, r *http.Request) {
	auditTrails, err := h.Manager.Repo.GetAllAuditTrails()
	if err != nil {
		log.Printf("Error retrieving audit trails: %v", err) // Log the error
		http.Error(w, "Appsouls Gateway Owner: Failed to retrieve audit trails", http.StatusInternalServerError)
		return
	}
	RespondWithJSON(w, http.StatusOK, auditTrails)
}
func (h *AuditTrailHandler) GetAllAuditTrailsHandler(w http.ResponseWriter, r *http.Request) {
	auditTrails, err := h.Manager.Repo.GetAllAuditTrails()
	fmt.Println(auditTrails)
	if err != nil {
		http.Error(w, "Failed to fetch audit trails", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(auditTrails)
}

// Handler function to get suspected logins
func (h *AuditTrailHandler) ListSuspectedUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Step 1: Extract the data from the request body
	var requestBody struct {
		Limit int    `json:"limit"`
		Date  string `json:"date"` // Optional: Add date if you want to filter by date
	}

	// Decode the JSON request body
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Step 2: Validate the limit (optional but recommended)
	if requestBody.Limit <= 0 {
		http.Error(w, "Limit must be greater than 0", http.StatusBadRequest)
		return
	}

	// Step 3: Use the Manager to call GetUsersWithMostFailedLogins
	// Pass the date and limit to the Manager function
	failedLogins, err := h.Manager.GetFailedLoginsByDate(requestBody.Date, requestBody.Limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching failed logins: %v", err), http.StatusInternalServerError)
		return
	}

	// Step 4: Respond with the data in JSON format
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(failedLogins)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
	}
}

// Leaderboard handles the "Online Leaderboard of users" request
// GET /api/audit/leaderboard?timePeriod=daily&limit=5
func (h *AuditTrailHandler) GetUserLeaderboardHandler(w http.ResponseWriter, r *http.Request) {
	timePeriod := r.URL.Query().Get("timePeriod")
	limitParam := r.URL.Query().Get("limit")
	limit := 10
	if limitParam != "" {
		parsedLimit, err := strconv.Atoi(limitParam)
		if err != nil || parsedLimit <= 0 {
			http.Error(w, "Invalid limit parameter", http.StatusBadRequest)
			return
		}
		limit = parsedLimit
	}

	validPeriods := map[string]bool{
		"hourly": true, "daily": true, "weekly": true, "fortnightly": true,
		"monthly": true, "quarterly": true, "half_yearly": true, "yearly": true,
	}
	if !validPeriods[timePeriod] {
		http.Error(w, "Invalid time period parameter", http.StatusBadRequest)
		return
	}

	leaderboard, err := h.Manager.Repo.GetUserLeaderboard(timePeriod, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching leaderboard: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(leaderboard)
}

// LongestSessions handles the "Users with longest live sessions" request
func (h *AuditTrailHandler) LongestSessions(w http.ResponseWriter, r *http.Request) {
	// Parse the limit and offset from query parameters
	limitStr := r.URL.Query().Get("limit")
	if limitStr == "" {
		limitStr = "10" // Default to 5 if limit is not provided
	}
	offsetStr := r.URL.Query().Get("offset")
	if offsetStr == "" {
		offsetStr = "0" // Default to 0 if offset is not provided
	}

	// Convert limit and offset to integers
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		http.Error(w, "Invalid limit value", http.StatusBadRequest)
		return
	}
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		http.Error(w, "Invalid offset value", http.StatusBadRequest)
		return
	}

	// Get the users with the longest sessions and the total count from the manager
	users, total, err := h.Manager.Repo.GetUsersWithLongestSessions(limit, offset)
	if err != nil {
		http.Error(w, "Failed to retrieve users with longest sessions", http.StatusInternalServerError)
		return
	}

	// Prepare the response
	response := map[string]interface{}{
		"total": total,
		"data":  users,
		"limit": limit,
		"draw":  1,
	}

	// Respond with JSON
	RespondWithJSON(w, http.StatusOK, response)
}

// MultipleDeviceLogins handles the "Users logging in from multiple devices/locations" request
func (h *AuditTrailHandler) MultipleDeviceLogins(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters for pagination
	queryParams := r.URL.Query()
	limitStr := queryParams.Get("limit")
	offsetStr := queryParams.Get("offset")

	// Set default values if parameters are not provided
	limit := 10 // Default limit
	offset := 0 // Default offset

	// Convert limit and offset to integers
	var err error
	if limitStr != "" {
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			http.Error(w, "Invalid limit parameter", http.StatusBadRequest)
			return
		}
	}

	if offsetStr != "" {
		offset, err = strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			http.Error(w, "Invalid offset parameter", http.StatusBadRequest)
			return
		}
	}

	// Call the manager function to get the users with multiple device logins
	users, total, err := h.Manager.GetUsersWithMultipleDeviceLogins(limit, offset)
	if err != nil {
		log.Printf("Failed to retrieve users: %v", err)
		http.Error(w, "Failed to retrieve users with multiple device logins", http.StatusInternalServerError)
		return
	}

	// Prepare the response with results and metadata
	response := map[string]interface{}{
		"data":  users,
		"total": total,
		"limit": limit,
		"draw":  1,
	}

	// Respond with the retrieved data as JSON
	RespondWithJSON(w, http.StatusOK, response)
}

// HandleFailedLoginsByDate handles requests to retrieve users with failed logins on a specific date
func (h *AuditTrailHandler) HandleFailedLoginsByDate(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	date := r.URL.Query().Get("date")
	limitParam := r.URL.Query().Get("limit")

	// Convert limit from string to int
	limit, err := strconv.Atoi(limitParam)
	if err != nil || limit <= 0 {
		http.Error(w, "Invalid limit parameter", http.StatusBadRequest)
		return
	}

	// Call the manager method
	results, err := h.Manager.GetFailedLoginsByDate(date, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write the response as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// HandleGetFailedLogins handles POST requests for retrieving failed logins
func (h *AuditTrailHandler) HandleGetFailedLogins(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse the JSON body
	var requestBody RequestBody
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Validate the parsed data
	if requestBody.Limit <= 0 {
		http.Error(w, "Limit must be greater than 0", http.StatusBadRequest)
		return
	}
	if requestBody.Date == "" {
		http.Error(w, "Date cannot be empty", http.StatusBadRequest)
		return
	}

	// Call the manager to get failed logins
	failedLogins, err := h.Manager.GetFailedLoginsByDate(requestBody.Date, requestBody.Limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch data: %v", err), http.StatusInternalServerError)
		return
	}

	// Respond with the data
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(failedLogins)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// DeleteAuditTrailHandler handles HTTP requests to delete an audit trail entry by ID.
func (h *AuditTrailHandler) Delete(w http.ResponseWriter, r *http.Request) {
	// Parse the ID from the URL query parameters (e.g., /delete?id=42)
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	// Convert the ID to an integer
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		http.Error(w, "invalid 'id' query parameter", http.StatusBadRequest)
		return
	}

	// Initialize the manager (this is just an example, adapt as needed for your project)
	manager := &AuditTrailManager{
		Repo: &AuditTrailRepository{DB: h.Manager.Repo.DB}, // Assume `db` is an initialized *sql.DB
	}

	// Call the delete method
	rowsAffected, err := manager.delete(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to delete record: %v", err), http.StatusInternalServerError)
		return
	}

	// Respond to the client
	response := map[string]interface{}{
		"message":     "record deleted successfully",
		"id":          id,
		"rowsDeleted": rowsAffected,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
