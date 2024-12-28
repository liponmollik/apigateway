package ddosprotection

import (
	"database/sql"
	"ddos_protectionHandler"
	"ddos_protectionRepository"
	"net/http"
)

// DdosProtectionService aggregates the repository and handler for DDoS protection
type DdosProtectionService struct {
	Repository *ddos_protectionRepository.DdosProtectionRepository
	Handler    *ddos_protectionHandler.DdosProtectionHandler
}

// NewDdosProtectionService initializes a new DDoS Protection Service
func NewDdosProtectionService(db *sql.DB) *DdosProtectionService {
	repo := ddos_protectionRepository.NewDdosProtectionRepository(db)
	handler := ddos_protectionHandler.NewDdosProtectionHandler(repo)
	return &DdosProtectionService{
		Repository: repo,
		Handler:    handler,
	}
}

// InitializeRoutes sets up the HTTP routes for DDoS protection
func (d *DdosProtectionService) InitializeRoutes() {
	http.HandleFunc("/api/v1/ddos/traffic-logs", d.Handler.GetTrafficLogsHandler)
	http.HandleFunc("/api/v1/ddos/traffic-logs/add", d.Handler.AddTrafficLogHandler)
	http.HandleFunc("/api/v1/ddos/ip-blacklist", d.Handler.GetIPBlacklistHandler)
	http.HandleFunc("/api/v1/ddos/ip-blacklist/add", d.Handler.AddIPBlacklistHandler)
	http.HandleFunc("/api/v1/ddos/ip-whitelist", d.Handler.GetIPWhitelistHandler)
	http.HandleFunc("/api/v1/ddos/ip-whitelist/add", d.Handler.AddIPWhitelistHandler)
	// Add more routes as needed
}
