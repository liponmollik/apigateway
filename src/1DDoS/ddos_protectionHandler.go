package ddos_protectionHandler

import (
	"encoding/json"
	"net/http"

	"ddos_protectionModel"
	"ddos_protectionRepository"
)

// DdosProtectionHandler is the handler struct that will use the repository
type DdosProtectionHandler struct {
	Repo *ddos_protectionRepository.DdosProtectionRepository
}

// NewDdosProtectionHandler initializes the handler with a repository instance
func NewDdosProtectionHandler(repo *ddos_protectionRepository.DdosProtectionRepository) *DdosProtectionHandler {
	return &DdosProtectionHandler{Repo: repo}
}

// AddTrafficLogHandler adds a traffic analysis log entry
func (h *DdosProtectionHandler) AddTrafficLogHandler(w http.ResponseWriter, r *http.Request) {
	var logEntry ddos_protectionModel.TrafficAnalysisLog
	err := json.NewDecoder(r.Body).Decode(&logEntry)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = h.Repo.AddTrafficAnalysisLog(logEntry)
	if err != nil {
		http.Error(w, "Failed to add traffic log", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode("Traffic log added successfully")
}

// GetTrafficLogsHandler retrieves all traffic analysis logs
func (h *DdosProtectionHandler) GetTrafficLogsHandler(w http.ResponseWriter, r *http.Request) {
	logs, err := h.Repo.GetTrafficAnalysisLogs()
	if err != nil {
		http.Error(w, "Failed to retrieve traffic logs", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(logs)
}

// AddRateLimitEntryHandler adds a rate limit entry for an IP
func (h *DdosProtectionHandler) AddRateLimitEntryHandler(w http.ResponseWriter, r *http.Request) {
	var entry ddos_protectionModel.IPRateLimit
	err := json.NewDecoder(r.Body).Decode(&entry)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = h.Repo.AddIPRateLimit(entry)
	if err != nil {
		http.Error(w, "Failed to add rate limit entry", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode("Rate limit entry added successfully")
}

// BlockIPHandler blocks an IP by adding it to the IP block list
func (h *DdosProtectionHandler) BlockIPHandler(w http.ResponseWriter, r *http.Request) {
	var ipEntry ddos_protectionModel.IPBlockList
	err := json.NewDecoder(r.Body).Decode(&ipEntry)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = h.Repo.AddIPBlockList(ipEntry)
	if err != nil {
		http.Error(w, "Failed to block IP", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode("IP blocked successfully")
}

// GetBlockedIPsHandler retrieves all blocked IPs
func (h *DdosProtectionHandler) GetBlockedIPsHandler(w http.ResponseWriter, r *http.Request) {
	blockedIPs, err := h.Repo.GetBlockedIPs()
	if err != nil {
		http.Error(w, "Failed to retrieve blocked IPs", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(blockedIPs)
}

// AddChallengeResultHandler logs the result of a challenge-response verification
func (h *DdosProtectionHandler) AddChallengeResultHandler(w http.ResponseWriter, r *http.Request) {
	var result ddos_protectionModel.ChallengeResponseResult
	err := json.NewDecoder(r.Body).Decode(&result)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = h.Repo.AddChallengeResponseResult(result)
	if err != nil {
		http.Error(w, "Failed to add challenge result", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode("Challenge result logged successfully")
}

// GetChallengeResultsHandler retrieves all challenge results
func (h *DdosProtectionHandler) GetChallengeResultsHandler(w http.ResponseWriter, r *http.Request) {
	results, err := h.Repo.GetChallengeResults()
	if err != nil {
		http.Error(w, "Failed to retrieve challenge results", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(results)
}

// AddGeoBlockHandler adds an entry to the geo-blocking list
func (h *DdosProtectionHandler) AddGeoBlockHandler(w http.ResponseWriter, r *http.Request) {
	var geoBlock ddos_protectionModel.GeoBlockList
	err := json.NewDecoder(r.Body).Decode(&geoBlock)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = h.Repo.AddGeoBlock(geoBlock)
	if err != nil {
		http.Error(w, "Failed to add geo-block entry", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode("Geo-block entry added successfully")
}

// GetGeoBlockListHandler retrieves all geo-blocking entries
func (h *DdosProtectionHandler) GetGeoBlockListHandler(w http.ResponseWriter, r *http.Request) {
	geoBlockList, err := h.Repo.GetGeoBlockList()
	if err != nil {
		http.Error(w, "Failed to retrieve geo-block list", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(geoBlockList)
}

// AddAccessPolicyHandler adds an access policy for IP whitelisting/blacklisting
func (h *DdosProtectionHandler) AddAccessPolicyHandler(w http.ResponseWriter, r *http.Request) {
	var policy ddos_protectionModel.AccessPolicy
	err := json.NewDecoder(r.Body).Decode(&policy)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = h.Repo.AddAccessPolicy(policy)
	if err != nil {
		http.Error(w, "Failed to add access policy", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode("Access policy added successfully")
}

// GetAccessPoliciesHandler retrieves all access policies
func (h *DdosProtectionHandler) GetAccessPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	policies, err := h.Repo.GetAccessPolicies()
	if err != nil {
		http.Error(w, "Failed to retrieve access policies", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(policies)
}

// AddProtocolFilterHandler adds an entry for protocol filtering
func (h *DdosProtectionHandler) AddProtocolFilterHandler(w http.ResponseWriter, r *http.Request) {
	var filter ddos_protectionModel.ProtocolFilter
	err := json.NewDecoder(r.Body).Decode(&filter)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = h.Repo.AddProtocolFilter(filter)
	if err != nil {
		http.Error(w, "Failed to add protocol filter", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode("Protocol filter added successfully")
}

// GetProtocolFiltersHandler retrieves all protocol filters
func (h *DdosProtectionHandler) GetProtocolFiltersHandler(w http.ResponseWriter, r *http.Request) {
	filters, err := h.Repo.GetProtocolFilters()
	if err != nil {
		http.Error(w, "Failed to retrieve protocol filters", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(filters)
}
