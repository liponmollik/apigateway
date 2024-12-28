package RateLimitingRepository

import (
	"RateLimitingModel" // Adjust the import path accordingly
	"time"

	"gorm.io/gorm"
)

// RateLimitingRepository provides methods for managing rate limiting data.
type RateLimitingRepository struct {
	db *gorm.DB
}

// NewRateLimitingRepository creates a new instance of RateLimitingRepository.
func NewRateLimitingRepository(db *gorm.DB) *RateLimitingRepository {
	return &RateLimitingRepository{db: db}
}

// SaveQuota saves a client's rate limit quota.
func (repo *RateLimitingRepository) SaveQuota(quota *RateLimitingModel.RateLimitQuota) error {
	return repo.db.Create(quota).Error
}

// GetQuota retrieves a client's rate limit quota by client ID.
func (repo *RateLimitingRepository) GetQuota(clientID string) (*RateLimitingModel.RateLimitQuota, error) {
	var quota RateLimitingModel.RateLimitQuota
	err := repo.db.Where("client_id = ?", clientID).First(&quota).Error
	return &quota, err
}

// UpdateQuota updates the quota values for a specific client.
func (repo *RateLimitingRepository) UpdateQuota(clientID string, updatedQuota *RateLimitingModel.RateLimitQuota) error {
	return repo.db.Model(&RateLimitingModel.RateLimitQuota{}).Where("client_id = ?", clientID).Updates(updatedQuota).Error
}

// SaveRequestCount increments or initializes request count for a client, IP, and endpoint.
func (repo *RateLimitingRepository) SaveRequestCount(count *RateLimitingModel.RequestCount) error {
	return repo.db.Save(count).Error
}

// GetRequestCount retrieves request count for a specific client, IP, and endpoint.
func (repo *RateLimitingRepository) GetRequestCount(clientID, ipAddress, endpoint string) (*RateLimitingModel.RequestCount, error) {
	var count RateLimitingModel.RequestCount
	err := repo.db.Where("client_id = ? AND ip_address = ? AND endpoint = ?", clientID, ipAddress, endpoint).First(&count).Error
	return &count, err
}

// SaveQuotaManagement saves a quota management record for a client.
func (repo *RateLimitingRepository) SaveQuotaManagement(quota *RateLimitingModel.QuotaManagement) error {
	return repo.db.Create(quota).Error
}

// UpdateQuotaUsage updates current usage for a client’s quota management.
func (repo *RateLimitingRepository) UpdateQuotaUsage(clientID string, newUsage int) error {
	return repo.db.Model(&RateLimitingModel.QuotaManagement{}).Where("client_id = ?", clientID).Update("current_usage", newUsage).Error
}

// SaveBurstControl saves burst control settings for a client.
func (repo *RateLimitingRepository) SaveBurstControl(burst *RateLimitingModel.BurstControl) error {
	return repo.db.Create(burst).Error
}

// UpdateBurstTimestamp updates the last burst timestamp for a client.
func (repo *RateLimitingRepository) UpdateBurstTimestamp(clientID string, timestamp time.Time) error {
	return repo.db.Model(&RateLimitingModel.BurstControl{}).Where("client_id = ?", clientID).Update("last_burst", timestamp).Error
}

// SaveSlidingWindowEntry saves a sliding window entry for a client.
func (repo *RateLimitingRepository) SaveSlidingWindowEntry(entry *RateLimitingModel.SlidingWindow) error {
	return repo.db.Create(entry).Error
}

// DeleteOldSlidingWindowEntries deletes sliding window entries older than a specified timestamp.
func (repo *RateLimitingRepository) DeleteOldSlidingWindowEntries(clientID string, before time.Time) error {
	return repo.db.Where("client_id = ? AND request_time < ?", clientID, before).Delete(&RateLimitingModel.SlidingWindow{}).Error
}

// SaveIpBasedLimit saves IP-based rate limiting information.
func (repo *RateLimitingRepository) SaveIpBasedLimit(limit *RateLimitingModel.IpBasedLimit) error {
	return repo.db.Create(limit).Error
}

// GetIpBasedLimit retrieves IP-based limit for a specific IP address.
func (repo *RateLimitingRepository) GetIpBasedLimit(ipAddress string) (*RateLimitingModel.IpBasedLimit, error) {
	var limit RateLimitingModel.IpBasedLimit
	err := repo.db.Where("ip_address = ?", ipAddress).First(&limit).Error
	return &limit, err
}

// SaveUserBasedLimit saves user-based rate limiting information.
func (repo *RateLimitingRepository) SaveUserBasedLimit(limit *RateLimitingModel.UserBasedLimit) error {
	return repo.db.Create(limit).Error
}

// GetUserBasedLimit retrieves user-based limit for a specific client.
func (repo *RateLimitingRepository) GetUserBasedLimit(clientID string) (*RateLimitingModel.UserBasedLimit, error) {
	var limit RateLimitingModel.UserBasedLimit
	err := repo.db.Where("client_id = ?", clientID).First(&limit).Error
	return &limit, err
}

// SavePenalty saves a penalty record for a client.
func (repo *RateLimitingRepository) SavePenalty(penalty *RateLimitingModel.Penalty) error {
	return repo.db.Create(penalty).Error
}

// GetPenalty retrieves the penalty record for a specific client.
func (repo *RateLimitingRepository) GetPenalty(clientID string) (*RateLimitingModel.Penalty, error) {
	var penalty RateLimitingModel.Penalty
	err := repo.db.Where("client_id = ?", clientID).First(&penalty).Error
	return &penalty, err
}

// SaveNotificationLog saves a notification or log entry for rate limiting events.
func (repo *RateLimitingRepository) SaveNotificationLog(log *RateLimitingModel.NotificationsAndLogging) error {
	return repo.db.Create(log).Error
}

// GetNotificationLogs retrieves all logs for a specific client.
func (repo *RateLimitingRepository) GetNotificationLogs(clientID string) ([]RateLimitingModel.NotificationsAndLogging, error) {
	var logs []RateLimitingModel.NotificationsAndLogging
	err := repo.db.Where("client_id = ?", clientID).Find(&logs).Error
	return logs, err
}
