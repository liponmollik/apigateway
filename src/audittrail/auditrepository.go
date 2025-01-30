package audittrail

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
)

// AuditTrailRepository handles database operations for the audit trail
type AuditTrailRepository struct {
	DB *sql.DB
}

// InsertAuditTrail inserts a record into app_user_audit_trail
func (repo *AuditTrailRepository) InsertAuditTrail(record *AppUserAuditTrail) error {
	query := `
		INSERT INTO app_user_audit_trail 
		(user_id, user_log_name, user_log_ip, user_log_datetime, user_agent, user_os, user_type, user_logout_date_time) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := repo.DB.Exec(query, record.UserID, record.UserLogName, record.UserLogIP, record.UserLogDatetime,
		record.UserAgent, record.UserOS, record.UserType, record.UserLogoutDateTime)
	return err
}

// InsertAuditTrailActivity inserts a record into app_user_audit_trail_activity
func (repo *AuditTrailRepository) InsertAuditTrailActivity(activity *AppUserAuditTrailActivity) error {
	query := `
		INSERT INTO app_user_audit_trail_activity 
		(user_act_userid, user_act_function_id) 
		VALUES (?, ?)
	`
	_, err := repo.DB.Exec(query, activity.UserActUserID, activity.UserActFunction)
	return err
}

// InsertAuditTrailIPInfo inserts a record into app_user_audit_trail_ip_info
func (repo *AuditTrailRepository) InsertAuditTrailIPInfo(ipInfo *AppUserAuditTrailIPInfo) error {
	query := `
		INSERT INTO app_user_audit_trail_ip_info 
		(user_login_ip_add, user_login_hostname, user_login_city, user_login_region_code, 
		user_login_country_name, user_login_latitude, user_login_longitude, user_login_org_code, user_login_zipcode) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := repo.DB.Exec(query, ipInfo.UserLoginIPAdd, ipInfo.UserLoginHostname, ipInfo.UserLoginCity, ipInfo.UserLoginRegion,
		ipInfo.UserLoginCountry, ipInfo.UserLoginLat, ipInfo.UserLoginLong, ipInfo.UserLoginOrg, ipInfo.UserLoginZip)
	return err
}

// InsertAuditTrailSuspect inserts a record into app_user_audit_trail_suspect
func (repo *AuditTrailRepository) InsertAuditTrailSuspect(suspect *AppUserAuditTrailSuspect) error {
	query := `
		INSERT INTO app_user_audit_trail_suspect 
		(user_login_user, user_login_password, user_login_ip, user_login_datetime, user_login_agent, user_login_os, user_login_type, number_try) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := repo.DB.Exec(query, suspect.UserLoginUser, suspect.UserLoginPass, suspect.UserLoginIP, suspect.UserLoginDatetime,
		suspect.UserLoginAgent, suspect.UserLoginOS, suspect.UserLoginType, suspect.NumberTry)
	return err
}

// GetAllAuditTrails retrieves all audit trail records from the database
func (repo *AuditTrailRepository) GetAllAuditTrails() ([]AppUserAuditTrail, error) {
	if repo.DB == nil {
		return nil, fmt.Errorf("database connection is not initialized")
	}

	// SQL query to fetch all records from the `app_user_audit_trail` table
	query := `SELECT 
                login_id, 
                user_id, 
                user_log_name, 
                user_log_ip, 
                user_log_datetime, 
                user_agent, 
                user_os, 
                user_type, 
                user_logout_date_time 
              FROM app_user_audit_trail`

	// Execute the query
	rows, err := repo.DB.Query(query)
	if err != nil {
		return nil, err // Return error if query fails
	}
	defer rows.Close() // Ensure rows are closed after processing

	// Slice to hold the results
	var auditTrails []AppUserAuditTrail

	// Iterate through the rows
	for rows.Next() {
		var trail AppUserAuditTrail

		// Scan each row into the AppUserAuditTrail struct
		err := rows.Scan(
			&trail.LoginID,
			&trail.UserID,
			&trail.UserLogName,
			&trail.UserLogIP,
			&trail.UserLogDatetime,
			&trail.UserAgent,
			&trail.UserOS,
			&trail.UserType,
			&trail.UserLogoutDateTime,
		)
		if err != nil {
			return nil, err // Return error if scanning fails
		}

		// Append the record to the results slice
		auditTrails = append(auditTrails, trail)
	}

	// Check for errors encountered during iteration
	if err = rows.Err(); err != nil {
		return nil, err
	}

	// Return the list of audit trails
	return auditTrails, nil
}

// GetUsersWithMostFailedLogins retrieves users with the highest number of failed login attempts
func (repo *AuditTrailRepository) GetUsersWithMostFailedLogins(limit int) ([]AppUserAuditTrailSuspect, error) {
	// SQL query to fetch users with the most failed login attempts
	// We avoid using `?` in LIMIT clause in MySQL by directly formatting the query string
	query := fmt.Sprintf(`SELECT 
                user_login_id, 
                user_login_user, 
                user_login_password, 
                user_login_ip, 
                user_login_datetime, 
                user_login_agent, 
                user_login_os, 
                user_login_type, 
                number_try 
              FROM app_user_audit_trail_suspect
              ORDER BY number_try DESC
              LIMIT %d`, limit)

	// Execute the query
	rows, err := repo.DB.Query(query)
	if err != nil {
		return nil, err // Return error if query execution fails
	}
	defer rows.Close() // Ensure rows are closed after processing

	// Slice to hold the results
	var failedLogins []AppUserAuditTrailSuspect

	// Iterate through the rows
	for rows.Next() {
		var suspect AppUserAuditTrailSuspect

		// Scan each row into the AppUserAuditTrailSuspect struct
		err := rows.Scan(
			&suspect.UserLoginID,
			&suspect.UserLoginUser,
			&suspect.UserLoginPass,
			&suspect.UserLoginIP,
			&suspect.UserLoginDatetime,
			&suspect.UserLoginAgent,
			&suspect.UserLoginOS,
			&suspect.UserLoginType,
			&suspect.NumberTry,
		)
		if err != nil {
			return nil, err // Return error if scanning fails
		}

		// Append the record to the results slice
		failedLogins = append(failedLogins, suspect)
	}

	// Check for errors encountered during iteration
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Return the list of users with the most failed logins
	return failedLogins, nil
}

// GetUsersWithMostFailedLoginsOnDate retrieves users with the highest number of failed login attempts on a specific date.
func (repo *AuditTrailRepository) GetUsersWithMostFailedLoginsOnDate(date string, limit int) ([]AppUserAuditTrailSuspect, error) {
	// Validate input parameters
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be greater than 0")
	}
	if date == "" {
		return nil, fmt.Errorf("date cannot be empty")
	}

	// SQL query to fetch users with the most failed login attempts on the given date
	query := `SELECT 
                user_login_id, 
                user_login_user, 
                user_login_password, 
                user_login_ip, 
                user_login_datetime, 
                user_login_agent, 
                user_login_os, 
                user_login_type, 
                number_try 
              FROM app_user_audit_trail_suspect
              WHERE DATE(user_login_datetime) = ?
              ORDER BY number_try DESC
              LIMIT ?`

	// Execute the query with the provided date and limit parameters
	rows, err := repo.DB.Query(query, date, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close() // Ensure rows are closed after processing

	// Slice to hold the results
	var failedLogins []AppUserAuditTrailSuspect

	// Iterate through the rows
	for rows.Next() {
		var suspect AppUserAuditTrailSuspect

		// Scan each row into the AppUserAuditTrailSuspect struct
		err := rows.Scan(
			&suspect.UserLoginID,
			&suspect.UserLoginUser,
			&suspect.UserLoginPass,
			&suspect.UserLoginIP,
			&suspect.UserLoginDatetime,
			&suspect.UserLoginAgent,
			&suspect.UserLoginOS,
			&suspect.UserLoginType,
			&suspect.NumberTry,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Append the record to the results slice
		failedLogins = append(failedLogins, suspect)
	}

	// Check for errors encountered during iteration
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error during row iteration: %w", err)
	}

	// Return the list of users with the most failed logins on the specified date
	return failedLogins, nil
}

// GetUserLeaderboard generates a leaderboard of users based on the number of logins in a specified time period
func (repo *AuditTrailRepository) GetUserLeaderboard(timePeriod string, limit int) ([]UserLoginLeaderboard, error) {
	var interval string
	switch timePeriod {
	case "hourly":
		interval = "HOUR"
	case "daily":
		interval = "DAY"
	case "weekly":
		interval = "WEEK"
	case "fortnightly":
		interval = "WEEK * 2"
	case "monthly":
		interval = "MONTH"
	case "quarterly":
		interval = "QUARTER"
	case "half_yearly":
		interval = "MONTH * 6"
	case "yearly":
		interval = "YEAR"
	default:
		return nil, fmt.Errorf("invalid time period: %s", timePeriod)
	}

	query := fmt.Sprintf(`
        SELECT 
            user_id, 
            user_log_name, 
            COUNT(*) AS login_count 
        FROM app_user_audit_trail 
        WHERE user_log_datetime >= DATE_SUB(NOW(), INTERVAL 1 %s)
        GROUP BY user_id, user_log_name
        ORDER BY login_count DESC
        LIMIT ?`, interval)

	rows, err := repo.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var leaderboard []UserLoginLeaderboard
	for rows.Next() {
		var entry UserLoginLeaderboard
		err := rows.Scan(&entry.UserID, &entry.UserName, &entry.LoginCount)
		if err != nil {
			return nil, err
		}
		leaderboard = append(leaderboard, entry)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return leaderboard, nil
}

// GetUsersWithLongestSessions retrieves users with the longest session durations with pagination
func (repo *AuditTrailRepository) GetUsersWithLongestSessions(limit, offset int) ([]UserSessionDuration, int, error) {
	// Query with LIMIT and OFFSET for pagination
	query := `
    SELECT 
        login_id as sessDataID,
		user_id AS UID, 
        user_log_name AS USERNAME,
        user_log_datetime AS LOGFEDIN,
        user_logout_date_time AS LOGDOUT,
        TIMESTAMPDIFF(SECOND, user_log_datetime, user_logout_date_time) AS SDURATION
    FROM app_user_audit_trail
    WHERE user_logout_date_time IS NOT NULL
    ORDER BY SDURATION DESC
    LIMIT ? OFFSET ?`

	// Execute the query
	rows, err := repo.DB.Query(query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	// Prepare the result set
	var results []UserSessionDuration
	for rows.Next() {
		var session UserSessionDuration
		err := rows.Scan(&session.DataID, &session.UserID, &session.UserName, &session.SessionLoginDate, &session.SessionLogoutDate, &session.SessionDuration)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan row: %w", err)
		}
		results = append(results, session)
	}

	// Check for errors during iteration
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating rows: %w", err)
	}

	// Query for total count of all records
	var total int
	countQuery := `SELECT COUNT(*) FROM app_user_audit_trail WHERE user_logout_date_time IS NOT NULL`
	err = repo.DB.QueryRow(countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve total count: %w", err)
	}

	return results, total, nil
}

func (repo *AuditTrailRepository) GetUsersWithMultipleDeviceLogins(limit, offset int) ([]LoginDeviceDetail, int, error) {
	// Query to fetch users with multiple device logins and pagination
	query := `SELECT 
				login_id as logid,
				user_id as uid,
				user_log_name as User,
				user_log_datetime as DTime,
				user_agent as uAgent,
				COUNT(DISTINCT user_log_ip) AS distinct_login_ips,
				COUNT(DISTINCT user_os) AS distinct_devices,
				user_type as uType
			FROM app_user_audit_trail
			GROUP BY uid, User
			LIMIT ? OFFSET ?`

	// Execute the query to fetch paginated results
	rows, err := repo.DB.Query(query, limit, offset)
	if err != nil {
		log.Printf("Query execution failed: %v", err)
		return nil, 0, err
	}
	defer rows.Close()

	// Parse the results
	var results []LoginDeviceDetail
	for rows.Next() {
		var user LoginDeviceDetail
		err := rows.Scan(&user.LoginID, &user.UserID, &user.UserLogName,
			&user.UserLogDatetime, &user.UserAgent, &user.UserLogIP,
			&user.UserOS, &user.UserType)
		if err != nil {
			log.Printf("Row scanning failed: %v", err)
			return nil, 0, err
		}
		results = append(results, user)
	}

	// Check for iteration errors
	if err = rows.Err(); err != nil {
		log.Printf("Row iteration error: %v", err)
		return nil, 0, err
	}

	// Query to get the total count of users with multiple device logins
	countQuery := `SELECT COUNT(*) FROM (
		SELECT user_id 
		FROM app_user_audit_trail
		GROUP BY user_id
	) AS subquery`

	var total int
	err = repo.DB.QueryRow(countQuery).Scan(&total)
	if err != nil {
		log.Printf("Total count query failed: %v", err)
		return nil, 0, err
	}

	// Return results, total count, and no error
	return results, total, nil
}

// Delete deletes a record from the specified table using a given condition.
// Parameters:
// - id: The ID or unique identifier for the record to delete.
// - table: The table name from which to delete the record.
// - condition: The WHERE clause condition (e.g., "id = ?").
func (repo *AuditTrailRepository) delete(id int) error {
	// Construct the query
	query := "DELETE FROM app_user_audit_trail WHERE login_id = ?"

	// Execute the query
	result, err := repo.DB.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to execute delete query: %w", err)
	}

	// Check the number of rows affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to retrieve the number of affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("no rows were deleted: record not found or already deleted")
	}

	return nil
}
