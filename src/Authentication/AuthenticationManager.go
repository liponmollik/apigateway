package Authentication

import (
	"AuthenticationModel"
	"AuthenticationRepository"
	"errors"
	"fmt"
	"strconv"
	"time"
)

type AuthManager struct {
	Repo *AuthenticationRepository.AuthRepository
}

func (m *AuthManager) AuthenticateUserByDevice(dType, uName, uPassword, uAPIKey string) (*AuthenticationRepository.User, error) {
	switch dType {
	case "mobile":
		phoneNo, err := strconv.Atoi(uName) // Assuming uName is phone number for mobile
		if err != nil {
			return nil, fmt.Errorf("invalid phone number")
		}
		return m.Repo.AuthenticateUserMobile(phoneNo, uAPIKey) // uAPIKey here represents the PIN
	case "desktop":
		return m.Repo.AuthenticateUser(uName, uPassword)
	default:
		return nil, fmt.Errorf("unsupported device type")
	}
}

// ValidateToken checks if a token is valid and not expired
func (m *AuthManager) ValidateToken(token string) (bool, error) {
	authToken, err := m.Repo.GetAuthTokenByToken(token)
	if err != nil {
		return false, err
	}

	if authToken.ExpiresAt.Before(time.Now()) {
		return false, errors.New("token expired")
	}

	return true, nil
}

// ValidateAPIKey checks if an API key is valid
func (m *AuthManager) ValidateAPIKey(apiKey string) (bool, error) {
	key, err := m.Repo.GetApiKeyByKey(apiKey)
	if err != nil {
		return false, err
	}

	if key.ExpiresAt.Before(time.Now()) {
		return false, errors.New("API key expired")
	}

	return true, nil
}

// GenerateOAuthToken generates a token based on client ID and authorization code
func (m *AuthManager) GenerateOAuthToken(clientID, code string) (string, error) {
	client, err := m.Repo.GetOAuthClientByClientID(clientID)
	if err != nil {
		return "", errors.New("client not found")
	}

	// Validate code here (omitting detailed logic for simplicity)

	// Generate token
	token := "generated_token" // replace with actual token generation logic
	authToken := AuthenticationModel.AuthToken{
		UserID:    client.ID,
		Token:     token,
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err = m.Repo.CreateAuthToken(authToken)
	if err != nil {
		return "", err
	}

	return token, nil
}

// CreateSSOSession creates a new SSO session for a user
func (m *AuthManager) CreateSSOSession(userID int64) (AuthenticationModel.Session, error) {
	session := AuthenticationModel.Session{
		UserID:       userID,
		SessionToken: "sso_generated_token", // Replace with actual token generation logic
		IsActive:     true,
		LastAccessed: time.Now(),
		ExpiresAt:    time.Now().Add(30 * time.Minute), // Set expiration for 30 minutes
		CreatedAt:    time.Now(),
		SessionData:  []string{"data1", "data2"}, // Replace with actual session data
	}

	err := m.Repo.CreateSession(session)
	if err != nil {
		return AuthenticationModel.Session{}, err
	}
	return session, nil
}

// GetSSOSession retrieves an SSO session by its ID
func (m *AuthManager) GetSSOSession(sessionID int64) (AuthenticationModel.Session, error) {
	session, err := m.Repo.GetSession(sessionID)
	if err != nil {
		return AuthenticationModel.Session{}, err
	}
	return session, nil
}

// UpdateSSOSession updates an existing SSO session
func (m *AuthManager) UpdateSSOSession(session AuthenticationModel.Session) error {
	return m.Repo.UpdateSession(session)
}

// DeleteSSOSession removes an SSO session by ID
func (m *AuthManager) DeleteSSOSession(sessionID int64) error {
	return m.Repo.DeleteSSOSession(sessionID)
}

// MFA Functions

// CreateMFAMethod adds a new MFA method for a user
func (m *AuthManager) CreateMFAMethod(userID int64, method AuthenticationModel.MFAMethod) error {
	method.UserID = userID
	return m.Repo.CreateMFAMethod(&method)
}

// GetMFAMethod retrieves an MFA method by its ID
func (m *AuthManager) GetMFAMethod(methodID int64) (AuthenticationModel.MFAMethod, error) {
	return m.Repo.GetMFAMethodByID(methodID)
}

// UpdateMFAMethod updates an existing MFA method
func (m *AuthManager) UpdateMFAMethod(method AuthenticationModel.MFAMethod) error {
	return m.Repo.UpdateMFAMethod(&method)
}

// DeleteMFAMethod removes an MFA method by ID
func (m *AuthManager) DeleteMFAMethod(methodID int64) error {
	return m.Repo.DeleteMFAMethod(methodID)
}

// Biometric Functions

// CreateBiometric adds a new biometric record for a user
func (m *AuthManager) CreateBiometric(userID int64, biometric AuthenticationModel.Biometric) error {
	biometric.UserID = userID
	return m.Repo.CreateBiometric(&biometric)
}

// GetBiometric retrieves a biometric record by user ID
func (m *AuthManager) GetBiometric(userID int64) (AuthenticationModel.Biometric, error) {
	return m.Repo.GetBiometricByUserID(userID)
}

// UpdateBiometric updates an existing biometric record
func (m *AuthManager) UpdateBiometric(biometric AuthenticationModel.Biometric) error {
	return m.Repo.UpdateBiometric(&biometric)
}

// DeleteBiometric removes a biometric record by user ID
func (m *AuthManager) DeleteBiometric(userID int64) error {
	return m.Repo.DeleteBiometric(userID)
}

// CreateSession creates a new session for a user
// CreateSession creates a new session for a user with detailed session data
func (m *AuthManager) CreateSession(userID int64, sessionToken string, sessionData AuthenticationModel.SessionData) (AuthenticationModel.Session, error) {
	if sessionToken == "" {
		return AuthenticationModel.Session{}, errors.New("session token cannot be empty")
	}

	session := AuthenticationModel.Session{
		UserID:       userID,
		SessionToken: sessionToken,
		IsActive:     true,
		LastAccessed: time.Now(),
		ExpiresAt:    time.Now().Add(30 * time.Minute), // Example expiration time
		CreatedAt:    time.Now(),
		SessionData:  []AuthenticationModel.SessionData{sessionData}, // Add session data
	}

	err := m.Repo.CreateSession(session)
	if err != nil {
		return AuthenticationModel.Session{}, err
	}
	return session, nil
}

// GetSession retrieves a session by its ID
func (m *AuthManager) GetSession(sessionID int64) (AuthenticationModel.Session, error) {
	if sessionID <= 0 {
		return AuthenticationModel.Session{}, errors.New("invalid session ID")
	}

	session, err := m.Repo.GetSession(sessionID)
	if err != nil {
		return AuthenticationModel.Session{}, err
	}
	return session, nil
}

// UpdateSession updates an existing session
func (m *AuthManager) UpdateSession(session AuthenticationModel.Session) error {
	if session.ID <= 0 {
		return errors.New("invalid session ID")
	}

	session.LastAccessed = time.Now() // Update last accessed time
	err := m.Repo.UpdateSession(session)
	if err != nil {
		return err
	}
	return nil
}

// DeleteSession removes a session by its ID
func (m *AuthManager) DeleteSession(sessionID int64) error {
	if sessionID <= 0 {
		return errors.New("invalid session ID")
	}

	err := m.Repo.DeleteSession(sessionID)
	if err != nil {
		return err
	}
	return nil
}

// GetSessionsByUserID retrieves all sessions for a specific user
func (m *AuthManager) GetSessionsByUserID(userID int64) ([]AuthenticationModel.Session, error) {
	if userID <= 0 {
		return nil, errors.New("invalid user ID")
	}

	sessions, err := m.Repo.GetSessionsByUserID(userID)
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// ValidateSession checks if a session is active and not expired
func (m *AuthManager) ValidateSession(sessionID int64) (bool, error) {
	session, err := m.GetSession(sessionID)
	if err != nil {
		return false, err
	}

	if !session.IsActive {
		return false, errors.New("session is inactive")
	}

	if session.ExpiresAt.Before(time.Now()) {
		return false, errors.New("session has expired")
	}

	return true, nil
}

// ExtendSession extends the expiration of an existing session
func (m *AuthManager) ExtendSession(sessionID int64, duration time.Duration) error {
	session, err := m.GetSession(sessionID)
	if err != nil {
		return err
	}

	if !session.IsActive {
		return errors.New("session is inactive")
	}

	session.ExpiresAt = session.ExpiresAt.Add(duration)
	err = m.Repo.UpdateSession(session)
	if err != nil {
		return err
	}

	return nil
}

// Other functions for Session, etc.
