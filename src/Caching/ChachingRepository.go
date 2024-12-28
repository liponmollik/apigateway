package auth

import (
	"database/sql"
	"fmt"
)

// UserRepository provides access to user data.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new UserRepository.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db}
}

// GetUserByID retrieves a user by their ID.
func (r *UserRepository) GetUserByID(userID int) (*User, error) {
	user := &User{}
	query := "select *FROM app_users WHERE user_id = ?"

	err := r.db.QueryRow(query, userID).Scan(
		&user.UserID,
		&user.UserParentID,
		&user.UserOrgID,
		&user.AddressID,
		&user.UserDistributorID,
		&user.UserPhoneNo,
		&user.UserEmailAddress,
		&user.UserSystemName,
		&user.UserGroup,
		&user.UserPin,
		&user.UserPassword,
		&user.UserSecretKey,
		&user.UserAPIAuthoKey,
		&user.UserFirstNameEN,
		&user.UserFirstNameNTV,
		&user.UserLastNameEN,
		&user.UserLastNameNTV,
		&user.UserType,
		&user.HasMultiCurrencySupport,
		&user.UserRegistrationDate,
		&user.UserStatus,
		&user.UserDateOfBirth,
		&user.UserTermsCondition,
		&user.UserEmailVerification,
		&user.CreateDate,
		&user.CreateBy,
		&user.ApprovalDate,
		&user.ApprovalBy,
		&user.LastUpdated,
		&user.LastUpdatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No user found
		}
		return nil, fmt.Errorf("error retrieving user: %v", err)
	}

	return user, nil
}

// AuthenticateUser checks the user credentials.
func (r *UserRepository) AuthenticateUser(userPin int, password string) (*User, error) {
	user := &User{}
	query := "SELECT address_id,user_system_name,user_phone_no FROM app_users WHERE user_phone_no=? and user_pin = ?"

	err := r.db.QueryRow(query, userPin).Scan(&user.UserPhoneNo, &user.UserPin)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No user found
		}
		return nil, fmt.Errorf("error authenticating user: %v", err)
	}

	// Verify the password
	if !user.VerifyPassword(password) {
		return nil, nil // Invalid password
	}

	return user, nil
}
