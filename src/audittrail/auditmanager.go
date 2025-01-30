package audittrail

import (
	"errors"
	"fmt"
)

// AuditTrailManager manages the business logic for audit trails
type AuditTrailManager struct {
	Repo *AuditTrailRepository
}

func (m *AuditTrailManager) GetAllAuditTrailsManager() ([]AuditTrail, error) {
	auditTrails, err := m.Repo.GetAllAuditTrails()
	if err != nil {
		return nil, err
	}

	var result []AuditTrail
	for _, trail := range auditTrails {
		result = append(result, AuditTrail{
			LoginID:            trail.LoginID, // Ensure this matches
			UserID:             trail.UserID,
			UserLogName:        trail.UserLogName,
			UserLogIP:          trail.UserLogIP,
			UserLogDatetime:    trail.UserLogDatetime,
			UserAgent:          trail.UserAgent,
			UserOS:             trail.UserOS,
			UserType:           trail.UserType,
			UserLogoutDateTime: trail.UserLogoutDateTime,
		})
	}

	return result, nil
}

// LogUserAction logs a user action to the audit trail activity
func (manager *AuditTrailManager) LogUserAction(userID int, functionID string) error {
	activity := &AppUserAuditTrailActivity{
		UserActUserID:   userID,
		UserActFunction: functionID,
	}
	return manager.Repo.InsertAuditTrailActivity(activity)
}

// LogUserIPInfo logs IP information to the audit trail IP info
func (manager *AuditTrailManager) LogUserIPInfo(ipInfo *AppUserAuditTrailIPInfo) error {
	return manager.Repo.InsertAuditTrailIPInfo(ipInfo)
}

// LogSuspect logs a suspect activity to the audit trail suspect
func (manager *AuditTrailManager) LogSuspect(suspect *AppUserAuditTrailSuspect) error {
	return manager.Repo.InsertAuditTrailSuspect(suspect)
}

// GetFailedLoginsByDate retrieves users with the highest failed login attempts on a specific date
func (manager *AuditTrailManager) GetFailedLoginsByDate(date string, limit int) ([]AppUserAuditTrailSuspect, error) {
	if date == "" {
		return nil, fmt.Errorf("date cannot be empty")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be greater than 0")
	}

	// Call the repository method to fetch data
	return manager.Repo.GetUsersWithMostFailedLoginsOnDate(date, limit)
}

// GetUsersWithMultipleDeviceLogins retrieves users with multiple device logins using pagination
func (m *AuditTrailManager) GetUsersWithMultipleDeviceLogins(limit, offset int) ([]LoginDeviceDetail, int, error) {
	return m.Repo.GetUsersWithMultipleDeviceLogins(limit, offset)
}

// Delete removes a record from the specified repository by ID.
func (m *AuditTrailManager) delete(id int) (int, error) {
	// Validate input
	if id <= 0 {
		return 0, errors.New("invalid ID: must be greater than zero")
	}

	// Call the repository's delete function
	err := m.Repo.delete(id)
	if err != nil {
		return 0, fmt.Errorf("failed to delete record with ID %d: %w", id, err)
	}

	// Return success with rows affected (1 in this case as delete by ID affects one row)
	return 1, nil
}
