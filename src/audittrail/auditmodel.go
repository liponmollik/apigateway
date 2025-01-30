package audittrail

import "time"

// AppUserAuditTrail represents the app_user_audit_trail table
type AppUserAuditTrail struct {
	LoginID            int       `json:"login_id"`
	UserID             int       `json:"user_id"`
	UserLogName        string    `json:"user_log_name"`
	UserLogIP          string    `json:"user_log_ip"`
	UserLogDatetime    time.Time `json:"user_log_datetime"`
	UserAgent          string    `json:"user_agent,omitempty"`
	UserOS             string    `json:"user_os"`
	UserType           string    `json:"user_type"`
	UserLogoutDateTime time.Time `json:"user_logout_date_time"`
}

// AppUserAuditTrailActivity represents the app_user_audit_trail_activity table
type AppUserAuditTrailActivity struct {
	UserActID       int    `json:"user_act_id"`
	UserActUserID   int    `json:"user_act_userid"`
	UserActFunction string `json:"user_act_function,omitempty"`
}

// AppUserAuditTrailIPInfo represents the app_user_audit_trail_ip_info table
type AppUserAuditTrailIPInfo struct {
	UserLoginID       int     `json:"user_login_id"`
	UserLoginIPAdd    string  `json:"user_login_ip_add,omitempty"`
	UserLoginHostname string  `json:"user_login_hostname,omitempty"`
	UserLoginCity     string  `json:"user_login_city,omitempty"`
	UserLoginRegion   string  `json:"user_login_region,omitempty"`
	UserLoginCountry  string  `json:"user_login_country,omitempty"`
	UserLoginLat      float64 `json:"user_login_lat,omitempty"`
	UserLoginLong     float64 `json:"user_login_long,omitempty"`
	UserLoginOrg      string  `json:"user_login_org,omitempty"`
	UserLoginZip      string  `json:"user_login_zip"`
}

// AppUserAuditTrailSuspect represents a record in the app_user_audit_trail_suspect table
type AppUserAuditTrailSuspect struct {
	UserLoginID       int       `json:"user_login_id"`
	UserLoginUser     string    `json:"user_login_user"`
	UserLoginPass     string    `json:"user_login_password"`
	UserLoginIP       string    `json:"user_login_ip"`
	UserLoginDatetime time.Time `json:"user_login_datetime"`
	UserLoginAgent    string    `json:"user_login_agent"`
	UserLoginOS       string    `json:"user_login_os"`
	UserLoginType     string    `json:"user_login_type"`
	NumberTry         int       `json:"number_try"`
}

// UserLoginLeaderboard represents a leaderboard entry for user logins
type UserLoginLeaderboard struct {
	UserID     int64  `json:"user_id"`
	UserName   string `json:"user_name"`
	LoginCount int    `json:"login_count"`
}

// UserSessionDuration represents a user's session duration details
type UserSessionDuration struct {
	DataID            int64  `json:"dataID"`
	UserID            int64  `json:"UserID"`
	UserName          string `json:"User"`
	SessionLoginDate  string `json:"LOGGEDIN"`
	SessionLogoutDate string `json:"LOGGEDOUT"`
	SessionDuration   int64  `json:"Duration"` // Duration in seconds
}

// UserLoginDetails represents details of a user who logged in from multiple devices or locations
type UserLoginDetails struct {
	UserID           int64  `json:"user_id"`
	UserName         string `json:"user_name"`
	DistinctLoginIPs int64  `json:"distinct_login_ips"` // Number of distinct IP addresses
	DistinctDevices  int64  `json:"distinct_devices"`   // Number of distinct devices (hostnames)
}

// RequestBody represents the structure of the JSON payload
type RequestBody struct {
	Limit int    `json:"limit"`
	Date  string `json:"date"`
}

type AuditTrail struct {
	LoginID            int // Add this if it's required
	UserID             int
	UserLogName        string
	UserLogIP          string
	UserLogDatetime    time.Time
	UserAgent          string
	UserOS             string
	UserType           string
	UserLogoutDateTime time.Time
}

type LoginDeviceDetail struct {
	LoginID            int // Add this if it's required
	UserID             int
	UserLogName        string
	UserLogIP          string
	UserLogDatetime    string
	UserAgent          string
	UserOS             string
	UserType           string
	UserLogoutDateTime time.Time
}

type DeleteRequest struct {
	dID     int `json:"data_id"`
	fnID    int `json:"function_id"`
	ActorID int `json:"user_id"`
}
