package authentication

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	PhoneNo             string     `json:"userPhoneNo" db:"user_phone_no"`
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

// Response structure to send JSON responses
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

var req struct {
	UserAccount   int    `json:"user_account"`
	UserPhone     int    `json:"Phone"`
	UserPin       int    `json:"user_pin"`
	UserPassword  string `json:"password"`
	loginModeType string `json:"loginModeType"` // "mobile" or "desktop"
	apiKEY        string `json:"uAPIKey"`
}

// SetPassword hashes and stores the password
var encryptedPassword string

// isValidEmail checks if the provided email is in a valid format.
func isValidEmail(email string) bool {
	// Simple regex for email validation
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

func setPassword(password string) error {
	if !isValidPassword(password) {
		return errors.New("invalid password format")
	}
	encryptedPassword = hashAndExtract(password)
	return nil
}

// GetPassword retrieves the stored password (hashed value)
func getPassword() (string, error) {
	if encryptedPassword == "" {
		return "", errors.New("no password is set")
	}
	return encryptedPassword, nil
}

// SetPIN hashes and stores the PIN
var encryptedPIN string

func setPIN(pin int) error {
	pinStr := fmt.Sprintf("%05d", pin) // Ensure PIN is 5 digits
	if !isValidPIN(pinStr) {
		return errors.New("invalid PIN format")
	}
	encryptedPIN = hashAndExtract(pinStr)
	return nil
}

// GetPIN retrieves the stored PIN (hashed value)
func getPIN() (string, error) {
	if encryptedPIN == "" {
		return "", errors.New("no PIN is set")
	}
	return encryptedPIN, nil
}

// Encrypt and substring
func hashAndExtract(password string) string {
	// Hash the password using SHA-256
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hashed := hasher.Sum(nil)

	// Convert the hashed bytes to a hex string
	hashedHex := hex.EncodeToString(hashed)

	// Extract the last 8 characters
	if len(hashedHex) < 8 {
		return hashedHex // Fallback in case the hash is unexpectedly short
	}
	return hashedHex[len(hashedHex)-8:]
}

// isValidPassword checks if the password meets the criteria.
func isValidPassword(password string) bool {
	if len(password) < 8 { // Updated length validation for better security
		return false
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	// Define special characters
	specialChars := "!@#$%^&*()-_=+[]{}|;:,.<>?"

	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case strings.ContainsRune(specialChars, ch):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

func isValidPIN(pin string) bool {
	re := regexp.MustCompile(`^\d{5}$`)
	return re.MatchString(pin)
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

	// Additional validation logic can be added here
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
	Status    int       `json:"Status"`
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
	ID          int64     `json:"id"`
	UserID      int64     `json:"user_id" validate:"required"`
	Method      string    `json:"method" validate:"required,oneof=sms email authenticator"`
	Destination string    `json:"destination" validate:"required"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	UpdatedAt     time.Time `json:"UpdatedAt"`
	Method        string    `json:"method" validate:"required"` // e.g., fingerprint, facial recognition
	Data          string    `json:"data" validate:"required"`   // The actual biometric data (e.g., template, image)
}

// Session represents a session for user access control
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
	ParentID      int64
	OrgID         int64
	AddrID        int64
	AccountNumber string
	DistributorID int64
	EmailAddress  string
	SystemName    string
	UserPhone     string // Optional for mobile login
	Key           string `json:"sesKey"`
	Value         string `json:"sesVal"`
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

type LoginRequest struct {
	APIKey        string `json:"api_key"`
	Token         string `json:"token,omitempty"`
	UserName      string `json:"UserName,omitempty"`
	LoginModeType string `json:"login_mode_type"`
	UserAccount   string `json:"user_account,omitempty"`
	UserPassword  string `json:"user_password,omitempty"`
	UserPhone     string `json:"user_phone,omitempty"`
	UserPin       string `json:"user_pin,omitempty"`
}

// Getter and Setter or SessionData value
func (s *Session) SetSessionData(data SessionData) error {
	// Marshal the SessionData struct into a JSON string
	serializedData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Append the serialized data to the SessionData field
	s.SessionData = append(s.SessionData, string(serializedData))
	return nil
}

// Convert JSON string back to map
func (s *Session) GetSessionData() (map[string]interface{}, error) {
	// Initialize the map to store the combined session data
	data := make(map[string]interface{})

	// Iterate over each string in SessionData (which is a []string)
	for _, sessionDataStr := range s.SessionData {
		// Temporary map for unmarshalling each session data string
		var tempData map[string]interface{}
		err := json.Unmarshal([]byte(sessionDataStr), &tempData)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
		}

		// Merge tempData into the main data map
		for key, value := range tempData {
			data[key] = value
		}
	}

	return data, nil
}

type APIError struct {
	Code    int
	Message string
}

// LoginResponse represents the response payload for login.
type LoginResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	SystemName   string `json:"systemName,omitempty"`
	SessionToken string `json:"sessionToken,omitempty"`
}

// Recognized login mode types
var validLoginModes = map[string]bool{
	"web":  true,
	"mob":  true,
	"desk": true,
	"iot":  true,
	"tv":   true,
	"tab":  true,
}

type rWeb struct {
	SessionToken string `json:"SessionToken"`
	APIKey       string `json:"APIKey"`
	UserName     string `json:"UserName"`
	UserPassword string `json:"UserPassword"`
	LoginMode    string `json:"LoginMode"`
}

type rMobile struct {
	SessionToken       string `json:"SessionToken"`
	SessionTokenExpire string `json:"SessionTokenExpire"`
	APIKey             string `json:"APIKey"`
	UserPhone          string `json:"UserPhone"`
	UserPIN            string `json:"UserPIN"`
	LoginMode          string `json:"LoginMode"`
}

type rDesktop struct {
	SessionToken       string `json:"SessionToken"`
	SessionTokenExpire string `json:"SessionTokenExpire"`
	APIKey             string `json:"APIKey"`
	UserName           string `json:"UserName"`
	UserPassword       string `json:"UserPassword"`
	LoginMode          string `json:"LoginMode"`
}

type rIOT struct {
	SessionToken       string `json:"SessionToken"`
	SessionTokenExpire string `json:"SessionTokenExpire"`
	APIKey             string `json:"api_key"`
	UserPhone          string `json:"UserPhone"`
	UserPIN            string `json:"UserPIN"`
	LoginMode          string `json:"LoginMode"`
	DeviceID           string `json:"DeviceID"`
	AddressID          string `json:"AddressID"`
}

type rTV struct {
	SessionToken       string `json:"SessionToken"`
	SessionTokenExpire string `json:"SessionTokenExpire"`
	APIKey             string `json:"APIKey"`
	UserName           string `json:"UserName"`
	UserPassword       string `json:"UserPassword"`
	LoginMode          string `json:"LoginMode"`
	DeviceID           string `json:"DeviceID"`
	AddressID          string `json:"AddressID"`
}
