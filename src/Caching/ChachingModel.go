package auth

import (
	"errors"
	"regexp"
	"time"
	"unicode"
)

// User represents the user model corresponding to the app_users table.
type User struct {
	UserID                  int        `json:"user_id"`
	UserParentID            int        `json:"user_parent_id"`
	UserOrgID               int        `json:"user_org_id"`
	AddressID               string     `json:"address_id"` // Updated field
	UserDistributorID       int        `json:"user_distributor_id"`
	UserPhoneNo             int        `json:"user_phone_no"`
	UserEmailAddress        string     `json:"user_email_address"`
	UserSystemName          string     `json:"user_system_name"`
	UserGroup               int        `json:"user_group"`
	UserPin                 int        `json:"user_pin"`
	UserPassword            string     `json:"user_password"`
	UserSecretKey           string     `json:"user_secret_key"`
	UserAPIAuthoKey         string     `json:"user_api_autho_key"`
	UserFirstNameEN         string     `json:"user_first_name_en"`
	UserFirstNameNTV        string     `json:"user_first_name_ntv"`
	UserLastNameEN          string     `json:"user_last_name_en"`
	UserLastNameNTV         string     `json:"user_last_name_ntv"`
	UserType                int        `json:"user_type"`
	HasMultiCurrencySupport int        `json:"has_multi_currency_support"`
	UserRegistrationDate    time.Time  `json:"user_registration_date"`
	UserStatus              int        `json:"user_status"`
	UserDateOfBirth         time.Time  `json:"user_date_of_birth"`
	UserTermsCondition      string     `json:"user_terms_condition"`
	UserEmailVerification   int        `json:"user_email_verification"`
	CreateDate              *time.Time `json:"create_date,omitempty"`
	CreateBy                *int       `json:"create_by,omitempty"`
	ApprovalDate            *time.Time `json:"approval_date,omitempty"`
	ApprovalBy              *int       `json:"approval_by,omitempty"`
	LastUpdated             *time.Time `json:"last_updated,omitempty"`
	LastUpdatedBy           *int       `json:"last_updated_by,omitempty"`

	// Relationship with Role
	RoleID int   `json:"role_id"`
	Role   *Role `json:"role,omitempty"` // Pointer to Role to avoid circular dependencies
}

// Role represents the role model which may have multiple users.
type Role struct {
	RoleID   int    `json:"role_id"`
	RoleName string `json:"role_name"`
}

// Validate validates user data before saving to the database.
func (u *User) Validate() error {
	if u.UserPhoneNo <= 0 {
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
