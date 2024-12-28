package Authentication

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// User represents the user model corresponding to the app_users table.
type User struct {
	ID                  int        `json:"userId" db:"user_id"`
	ParentID            int        `json:"userParentId" db:"user_parent_id"`
	OrgID               int        `json:"userOrgId" db:"user_org_id"`
	AddrID              *string    `json:"addressId,omitempty" db:"address_id"` // Nullable
	AccountNumber       int64      `json:"accountNo" db:"account_no"`
	DistributorID       int        `json:"userDistributorId" db:"user_distributor_id"`
	PhoneNo             int        `json:"userPhoneNo" db:"user_phone_no"`
	EmailAddress        *string    `json:"userEmailAddress,omitempty" db:"user_email_address"` // Nullable
	SystemName          *string    `json:"uName,omitempty" db:"user_system_name"`              // Nullable
	Group               int        `json:"userGroup" db:"user_group"`
	PIN                 int        `json:"userPin" db:"user_pin"`
	Password            *string    `json:"uPassword,omitempty" db:"user_password"`              // Nullable
	SecretKey           *string    `json:"userSecretKey,omitempty" db:"user_secret_key"`        // Nullable
	APIAuthKey          *string    `json:"uAPIKey,omitempty" db:"user_api_autho_key"`           // Nullable
	FirstNameEN         *string    `json:"userFirstNameEn,omitempty" db:"user_frist_name_en"`   // Nullable
	FirstNameNtv        *string    `json:"userFirstNameNtv,omitempty" db:"user_frist_name_ntv"` // Nullable
	LastNameEN          *string    `json:"userLastNameEn,omitempty" db:"user_last_name_en"`     // Nullable
	LastNameNtv         *string    `json:"userLastNameNtv,omitempty" db:"user_last_name_ntv"`   // Nullable
	Type                int        `json:"userType" db:"user_type"`
	MultiCurrencyCrypto bool       `json:"hasMultiCurrencyCrypto" db:"has_mmulti_currency_crypto"`
	MultiCurrencyUSD    *bool      `json:"hasMultiCurrencyUsd,omitempty" db:"has_mmulti_currency_usd"` // Nullable
	MultiCurrencyGBP    *bool      `json:"hasMultiCurrencyGbp,omitempty" db:"has_mmulti_currency_gbp"` // Nullable
	MultiCurrencyBDT    *bool      `json:"hasMultiCurrencyBdt,omitempty" db:"has_mmulti_currency_bdt"` // Nullable
	MultiCurrencyINR    *bool      `json:"hasMultiCurrencyInr,omitempty" db:"has_mmulti_currency_inr"` // Nullable
	MultiCurrencyEUR    *bool      `json:"hasMultiCurrencyEur,omitempty" db:"has_mmulti_currency_eur"` // Nullable
	MultiCurrencyAED    *bool      `json:"hasMultiCurrencyAed,omitempty" db:"has_mmulti_currency_aed"` // Nullable
	RegistrationDate    time.Time  `json:"userRegistrationDate" db:"user_registration_date"`
	Status              bool       `json:"userStatus" db:"user_status"`
	DateOfBirth         time.Time  `json:"userDateOfBirth" db:"user_date_of_birth"`
	TermsCondition      string     `json:"userTermsCondition" db:"user_terms_condition"`
	EmailVerification   bool       `json:"userEmailVerification" db:"user_email_verification"`
	CreatedBy           *int       `json:"createBy,omitempty" db:"create_by"`         // Nullable
	VerifiedBy          *int       `json:"verifyBy,omitempty" db:"verify_by"`         // Nullable
	ValidatedBy         *int       `json:"validateBy,omitempty" db:"validate_by"`     // Nullable
	ApprovedBy          *int       `json:"approvalBy,omitempty" db:"approval_by"`     // Nullable
	ModifiedBy          *int       `json:"modifyBy,omitempty" db:"modify_by"`         // Nullable
	CreatedDate         *time.Time `json:"createDate,omitempty" db:"create_date"`     // Nullable
	VerifiedDate        *time.Time `json:"verifyDate,omitempty" db:"verify_date"`     // Nullable
	ValidatedDate       *time.Time `json:"validateDate,omitempty" db:"validate_date"` // Nullable
	ApprovedDate        *time.Time `json:"approvalDate,omitempty" db:"approval_date"` // Nullable
	ModifiedDate        *time.Time `json:"modifyDate,omitempty" db:"modify_date"`     // Nullable

	// Relationship with Role
	RoleID int   `json:"roleId" db:"role_id"`
	Role   *Role `json:"role,omitempty"` // Pointer to Role to avoid circular dependencies
}

// Role represents the role model which may have multiple users.
type Role struct {
	RoleID   int    `json:"role_id"`
	RoleName string `json:"role_name"`
}

// Validate validates user data before saving to the database.
func (u *User) Validate() error {
	if !ValidatePhoneNumber(u.PhoneNo) {
		return errors.New("invalid phone number")
	}
	if !isValidEmail(u.UserEmailAddress) {
		return errors.New("invalid email format")
	}
	if len(u.UserPassword) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

// isValidEmail checks if the provided email is in a valid format.
func isValidEmail(email string) bool {
	// Simple regex for email validation
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// VerifyPassword checks if the provided password matches the user's password.
func (u *User) VerifyPassword(password string) bool {
	// Check password validity
	if !isValidPassword(password) {
		return false
	}

	// Implement hashing verification here (use bcrypt or similar)
	// For demonstration, assuming plain text matching for hashed passwords.
	return u.UserPassword == password // Replace with actual hash comparison
}

// isValidPassword checks if the password meets the criteria.
func isValidPassword(password string) bool {
	if len(password) != 6 {
		return false
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	// Define special characters
	specialChars := "!@#$%^&*()-_=+[]{}|;:,.<>?"

	for _, ch := range password {
		if unicode.IsUpper(ch) {
			hasUpper = true
		} else if unicode.IsLower(ch) {
			hasLower = true
		} else if unicode.IsDigit(ch) {
			hasDigit = true
		} else if contains(specialChars, ch) {
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// ValidatePhoneNumber checks if a phone number is valid based on specific prefixes and length.
func ValidatePhoneNumber(phone string) (bool, error) {
	// Trim whitespace
	phone = strings.TrimSpace(phone)

	// Check if phone number is empty
	if phone == "" {
		return false, errors.New("phone number is empty")
	}

	// Regular expression to match phone numbers that start with specified prefixes and have exactly 11 digits
	phoneRegex := regexp.MustCompile(`^(011|012|013|014|015|016|017|018|019)[0-9]{8}$`)

	// Check if the phone number matches the pattern
	if !phoneRegex.MatchString(phone) {
		return false, errors.New("invalid phone number format or prefix")
	}

	// Additional logic could go here, such as checking if the number is in a blacklist

	return true, nil
}

// AuthToken represents a token for user authentication
type AuthToken struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id" validate:"required"`
	Token     string    `json:"token" validate:"required,min=32"`
	TokenType string    `json:"token_type" validate:"required,oneof=jwt oauth"`
	ExpiresAt time.Time `json:"expires_at" validate:"required"`
	CreatedAt time.Time `json:"created_at"`
}

// ApiKey represents API key details for authentication
type ApiKey struct {
	ID        int64     `json:"id"`
	Key       string    `json:"key" validate:"required,min=32"`
	ClientID  string    `json:"client_id" validate:"required"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OAuthClient represents an OAuth client for the system
type OAuthClient struct {
	ID           int64  `json:"id"`
	ClientID     string `json:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required,min=32"`
	RedirectURI  string `json:"redirect_uri" validate:"required,url"`
	Scope        string `json:"scope" validate:"required"`
	GrantType    string `json:"grant_type" validate:"required,oneof=authorization_code client_credentials"`
}

// SSOSession represents a Single Sign-On session
type SSOSession struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id" validate:"required"`
	SessionID string    `json:"session_id" validate:"required,min=32"`
	ExpiresAt time.Time `json:"expires_at" validate:"required"`
	CreatedAt time.Time `json:"created_at"`
}

// MFAMethod represents a Multi-Factor Authentication method for a user
type MFAMethod struct {
	ID          int64  `json:"id"`
	UserID      int64  `json:"user_id" validate:"required"`
	Method      string `json:"method" validate:"required,oneof=sms email authenticator"`
	Destination string `json:"destination" validate:"required"`
}

// PasswordAuth represents a password-based authentication record
type PasswordAuth struct {
	ID           int64     `json:"id"`
	UserID       int64     `json:"user_id" validate:"required"`
	PasswordHash string    `json:"password_hash" validate:"required,min=60"`
	Salt         string    `json:"salt" validate:"required,min=16"`
	CreatedAt    time.Time `json:"created_at"`
}

// Biometric represents biometric data for user authentication
type Biometric struct {
	ID            int64     `json:"id"`
	UserID        int64     `json:"user_id" validate:"required"`
	BiometricHash string    `json:"biometric_hash" validate:"required"`
	CreatedAt     time.Time `json:"created_at"`
}

// Session represents a session for user access control
type Session struct {
	ID          int64     `json:"id"`
	UserID      int64     `json:"user_id" validate:"required"`
	SessionID   string    `json:"session_id" validate:"required,min=32"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	SessionData []string  `json:"session_data" validate:"required"` // New field for storing multiple session data
}

type Session struct {
	ID           int64     `json:"id"`
	UserID       int64     `json:"user_id"`
	SessionToken string    `json:"session_token"`
	IsActive     bool      `json:"is_active"`
	LastAccessed time.Time `json:"last_accessed"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	SessionData  []string  `json:"session_data" validate:"required"` // New field for storing multiple session data
}

type SessionData struct {
	ParentID      int64  `json:"parent_id"`
	OrgID         int64  `json:"org_id"`
	AddrID        int64  `json:"addr_id"`
	AccountNumber string `json:"account_number"`
	DistributorID int64  `json:"distributor_id"`
	EmailAddress  string `json:"email_address"`
	SystemName    string `json:"system_name"`
}

// RefreshToken represents a token used to refresh user sessions
type RefreshToken struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id" validate:"required"`
	Token     string    `json:"token" validate:"required,min=32"`
	ExpiresAt time.Time `json:"expires_at" validate:"required"`
	CreatedAt time.Time `json:"created_at"`
}

// DeviceFingerprint represents a device's fingerprint for identification purposes
type DeviceFingerprint struct {
	ID          int64     `json:"id"`
	UserID      int64     `json:"user_id" validate:"required"`
	Fingerprint string    `json:"fingerprint" validate:"required,min=32"`
	DeviceType  string    `json:"device_type" validate:"required"`
	LastUsedAt  time.Time `json:"last_used_at"`
}

// LoginAttempt logs login attempts for auditing and security purposes
type LoginAttempt struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id" validate:"required"`
	Timestamp time.Time `json:"timestamp" validate:"required"`
	Success   bool      `json:"success"`
	IPAddress string    `json:"ip_address" validate:"required,ipv4|ipv6"`
}

// AuthEventLog records important authentication-related events
type AuthEventLog struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id" validate:"required"`
	Event     string    `json:"event" validate:"required"`
	Timestamp time.Time `json:"timestamp" validate:"required"`
	IPAddress string    `json:"ip_address" validate:"required,ipv4|ipv6"`
}

// Getter and Setter or SessionData value
// Convert map to JSON string for storage
func (s *Session) SetSessionData(data map[string]interface{}) error {
	serializedData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	s.SessionData = string(serializedData)
	return nil
}

// Convert JSON string back to map
func (s *Session) GetSessionData() (map[string]interface{}, error) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(s.SessionData), &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}
