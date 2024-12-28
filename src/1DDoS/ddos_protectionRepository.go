package ddos_protectionRepository

import (
	"database/sql"
	"time"

	"ddos_protectionModel" // Import the package containing the model structs
)

// DdosProtectionRepository defines methods for CRUD operations and reports
type DdosProtectionRepository struct {
	db *sql.DB
}

// NewDdosProtectionRepository initializes a new repository
func NewDdosProtectionRepository(db *sql.DB) *DdosProtectionRepository {
	return &DdosProtectionRepository{db: db}
}

// Traffic Analysis CRUD Operations
func (repo *DdosProtectionRepository) AddTrafficAnalysisLog(log ddos_protectionModel.TrafficAnalysisLog) error {
	query := "INSERT INTO traffic_analysis_log (timestamp, detected_anomaly, request_volume, detection_method, notes) VALUES (?, ?, ?, ?, ?)"
	_, err := repo.db.Exec(query, log.Timestamp, log.DetectedAnomaly, log.RequestVolume, log.DetectionMethod, log.Notes)
	return err
}

func (repo *DdosProtectionRepository) GetTrafficAnalysisLogs() ([]ddos_protectionModel.TrafficAnalysisLog, error) {
	rows, err := repo.db.Query("SELECT id, timestamp, detected_anomaly, request_volume, detection_method, notes FROM traffic_analysis_log")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := []ddos_protectionModel.TrafficAnalysisLog{}
	for rows.Next() {
		var log ddos_protectionModel.TrafficAnalysisLog
		if err := rows.Scan(&log.ID, &log.Timestamp, &log.DetectedAnomaly, &log.RequestVolume, &log.DetectionMethod, &log.Notes); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

// Example analytical function: GetDailyAnomalyCount
func (repo *DdosProtectionRepository) GetDailyAnomalyCount(date time.Time) (int, error) {
	query := "SELECT COUNT(*) FROM traffic_analysis_log WHERE detected_anomaly = true AND DATE(timestamp) = DATE(?)"
	var count int
	err := repo.db.QueryRow(query, date).Scan(&count)
	return count, err
}

// IP Rate Limiting CRUD Operations
func (repo *DdosProtectionRepository) AddIPRateLimitingLog(log ddos_protectionModel.IPRateLimitingLog) error {
	query := "INSERT INTO ip_rate_limiting_log (timestamp, ip_address, request_count, rate_limit, action_taken) VALUES (?, ?, ?, ?, ?)"
	_, err := repo.db.Exec(query, log.Timestamp, log.IPAddress, log.RequestCount, log.RateLimit, log.ActionTaken)
	return err
}

// Challenge-Response Verification CRUD Operations
func (repo *DdosProtectionRepository) AddChallengeResponseLog(log ddos_protectionModel.ChallengeResponseLog) error {
	query := "INSERT INTO challenge_response_log (timestamp, ip_address, challenge_issued, response_status, response_time) VALUES (?, ?, ?, ?, ?)"
	_, err := repo.db.Exec(query, log.Timestamp, log.IPAddress, log.ChallengeIssued, log.ResponseStatus, log.ResponseTime)
	return err
}

// Example analytical function: GetChallengeSuccessRate
func (repo *DdosProtectionRepository) GetChallengeSuccessRate() (float64, error) {
	query := "SELECT (SELECT COUNT(*) FROM challenge_response_log WHERE response_status = 'solved') * 1.0 / COUNT(*) FROM challenge_response_log"
	var rate float64
	err := repo.db.QueryRow(query).Scan(&rate)
	return rate, err
}

// Geo-Blocking CRUD Operations
func (repo *DdosProtectionRepository) AddGeoBlockingLog(log ddos_protectionModel.GeoBlockingLog) error {
	query := "INSERT INTO geo_blocking_log (timestamp, ip_address, region, action_taken, reason) VALUES (?, ?, ?, ?, ?)"
	_, err := repo.db.Exec(query, log.Timestamp, log.IPAddress, log.Region, log.ActionTaken, log.Reason)
	return err
}

// Access Policies CRUD Operations
func (repo *DdosProtectionRepository) AddAccessPolicyLog(log ddos_protectionModel.AccessPolicyLog) error {
	query := "INSERT INTO access_policy_log (timestamp, ip_address, action_taken, policy_type, reason) VALUES (?, ?, ?, ?, ?)"
	_, err := repo.db.Exec(query, log.Timestamp, log.IPAddress, log.ActionTaken, log.PolicyType, log.Reason)
	return err
}

// Protocol Validation CRUD Operations
func (repo *DdosProtectionRepository) AddProtocolValidationLog(log ddos_protectionModel.ProtocolValidationLog) error {
	query := "INSERT INTO protocol_validation_log (timestamp, ip_address, request_headers, validation_status, reason) VALUES (?, ?, ?, ?, ?)"
	_, err := repo.db.Exec(query, log.Timestamp, log.IPAddress, log.RequestHeaders, log.ValidationStatus, log.Reason)
	return err
}

// Connection Rate Control CRUD Operations
func (repo *DdosProtectionRepository) AddConnectionRateControlLog(log ddos_protectionModel.ConnectionRateControlLog) error {
	query := "INSERT INTO connection_rate_control_log (timestamp, ip_address, connection_status, current_connection_count, max_connections_allowed) VALUES (?, ?, ?, ?, ?)"
	_, err := repo.db.Exec(query, log.Timestamp, log.IPAddress, log.ConnectionStatus, log.CurrentConnectionCount, log.MaxConnectionsAllowed)
	return err
}

// Traffic Throttling CRUD Operations
func (repo *DdosProtectionRepository) AddTrafficThrottlingLog(log ddos_protectionModel.TrafficThrottlingLog) error {
	query := "INSERT INTO traffic_throttling_log (timestamp, ip_address, request_count, throttle_status, reason) VALUES (?, ?, ?, ?, ?)"
	_, err := repo.db.Exec(query, log.Timestamp, log.IPAddress, log.RequestCount, log.ThrottleStatus, log.Reason)
	return err
}

// Behavioral Signature CRUD Operations
func (repo *DdosProtectionRepository) AddBehavioralSignatureLog(log ddos_protectionModel.BehavioralSignatureLog) error {
	query := "INSERT INTO behavioral_signature_log (timestamp, ip_address, matched_pattern, action_taken, threat_level, notes) VALUES (?, ?, ?, ?, ?, ?)"
	_, err := repo.db.Exec(query, log.Timestamp, log.IPAddress, log.MatchedPattern, log.ActionTaken, log.ThreatLevel, log.Notes)
	return err
}

// DDoS Protection Summary CRUD Operations
func (repo *DdosProtectionRepository) AddDdosProtectionSummary(summary ddos_protectionModel.DdosProtectionSummary) error {
	query := "INSERT INTO ddos_protection_summary (date, total_anomalies_detected, total_ips_blocked, total_challenges_issued, total_challenges_solved, total_geo_blocks, total_connections_blocked, total_throttled_requests, total_signature_matches) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
	_, err := repo.db.Exec(query, summary.Date, summary.TotalAnomaliesDetected, summary.TotalIPsBlocked, summary.TotalChallengesIssued, summary.TotalChallengesSolved, summary.TotalGeoBlocks, summary.TotalConnectionsBlocked, summary.TotalThrottledRequests, summary.TotalSignatureMatches)
	return err
}

// Analytical Report Example: GetDailyReport
func (repo *DdosProtectionRepository) GetDailyReport(date time.Time) (*ddos_protectionModel.DdosProtectionSummary, error) {
	query := `
        SELECT 
            total_anomalies_detected,
            total_ips_blocked,
            total_challenges_issued,
            total_challenges_solved,
            total_geo_blocks,
            total_connections_blocked,
            total_throttled_requests,
            total_signature_matches
        FROM ddos_protection_summary
        WHERE date = ?
    `
	var summary ddos_protectionModel.DdosProtectionSummary
	err := repo.db.QueryRow(query, date).Scan(
		&summary.TotalAnomaliesDetected,
		&summary.TotalIPsBlocked,
		&summary.TotalChallengesIssued,
		&summary.TotalChallengesSolved,
		&summary.TotalGeoBlocks,
		&summary.TotalConnectionsBlocked,
		&summary.TotalThrottledRequests,
		&summary.TotalSignatureMatches,
	)
	if err != nil {
		return nil, err
	}
	return &summary, nil
}
