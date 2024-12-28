package RateLimitingManager

import (
	"RateLimitingModel"      // Adjust the import path accordingly
	"RateLimitingRepository" // Adjust the import path accordingly
)

// RateLimitingManager provides methods to manage rate limiting logic.
type RateLimitingManager struct {
	repo *RateLimitingRepository.RateLimitingRepository
}

// NewRateLimitingManager creates a new instance of RateLimitingManager.
func NewRateLimitingManager(repo *RateLimitingRepository.RateLimitingRepository) *RateLimitingManager {
	return &RateLimitingManager{repo: repo}
}

// CreateOrUpdateQuota creates or updates a client's rate limit quota.
func (m *RateLimitingManager) CreateOrUpdateQuota(quota *RateLimitingModel.RateLimitQuota) error {
	existingQuota, err := m.repo.GetQuota(quota.ClientID)
	if err != nil {
		if err.Error() == "record not found" {
			// If quota does not exist, create it
			return m.repo.SaveQuota(quota)
		}
		return err
	}
	// If quota exists, update it
	return m.repo.UpdateQuota(existingQuota.ClientID, quota)
}

// RecordRequestCount records a request count for a client, IP, and endpoint.
func (m *RateLimitingManager) RecordRequestCount(clientID, ipAddress, endpoint string) error {
	count, err := m.repo.GetRequestCount(clientID, ipAddress, endpoint)
	if err != nil {
		if err.Error() == "record not found" {
			// If count does not exist, create it
			newCount := &RateLimitingModel.RequestCount{
				ClientID:  clientID,
				IPAddress: ipAddress,
				Endpoint:  endpoint,
				Count:     1, // Initialize to 1
			}
			return m.repo.SaveRequestCount(newCount)
		}
		return err
	}
	// If count exists, increment it
	count.Count++
	return m.repo.SaveRequestCount(count)
}

// ManageBurstControl manages burst control settings for a client.
func (m *RateLimitingManager) ManageBurstControl(burst *RateLimitingModel.BurstControl) error {
	return m.repo.SaveBurstControl(burst)
}

// UpdateQuotaUsage updates current usage for a client's quota management.
func (m *RateLimitingManager) UpdateQuotaUsage(clientID string, newUsage int) error {
	return m.repo.UpdateQuotaUsage(clientID, newUsage)
}

// GetNotificationLogs retrieves all logs for a specific client.
func (m *RateLimitingManager) GetNotificationLogs(clientID string) ([]RateLimitingModel.NotificationsAndLogging, error) {
	return m.repo.GetNotificationLogs(clientID)
}

// Add additional methods for other functionalities as needed...
