package authentication

import (
	"errors"
	"fmt"
	"time"
)

type AuthManager struct {
	Repo *AuthRepository
}

func (m *AuthManager) LoginManagerWeb(uName, uPassword string) (*rWeb, error) {

	//Fetch user data
	user, err := m.Repo.getUserAndPassword(uName, uPassword)
	if err != nil {
		return nil, err
	}

	// Add loginMode and APIKey if necessary
	//user.LoginMode = loginModeType
	//user.APIKey = APIKey

	return user, nil
}

func (m *AuthManager) LoginManagerMobile(loginModeType, phoneNo, pinNo, APIKey string) (*User, error) {
	switch loginModeType {
	case "mob":
		return m.Repo.getPhoneAndPIN(phoneNo, pinNo)
	default:
		return nil, fmt.Errorf("unsupported login mode type")
	}
}

func (m *AuthManager) LoginManagerDesktop(loginModeType, uName, uPassword, APIKey string) (*rWeb, error) {
	loginModeType = "web" // Assuming you want to set loginModeType to "web"
	return m.Repo.getUserAndPassword(uName, uPassword)
}

func (m *AuthManager) LoginManagerTV(loginModeType, uName, uPassword, APIKey string) (*rWeb, error) {
	loginModeType = "web" // Assuming you want to set loginModeType to "web"
	return m.Repo.getUserAndPassword(uName, uPassword)
}
func (m *AuthManager) LoginManagerTab(loginModeType, phoneNo, pinNo, APIKey string) (*User, error) {
	switch loginModeType {
	case "tab":
		return m.Repo.getPhoneAndPIN(phoneNo, pinNo)

	default:
		return nil, fmt.Errorf("unsupported login mode type")
	}
}

func (m *AuthManager) LoginManagerIOT(loginModeType, phoneNo, pinNo, APIKey string) (*User, error) {
	switch loginModeType {
	case "iot":
		return m.Repo.getPhoneAndPIN(phoneNo, pinNo)
	default:
		return nil, fmt.Errorf("unsupported login mode type")
	}
}

// ValidateToken checks if a token is valid and not expired
func (m *AuthManager) ValidateTokenManager(token string) (bool, error) {
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
	authToken := AuthToken{
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
func (m *AuthManager) CreateSSOSession(userID int64) (Session, error) {
	session := Session{
		UserID:       userID,
		SessionToken: "sso_generated_token", // Replace with actual token generation logic
		IsActive:     true,
		LastAccessed: time.Now(),
		ExpiresAt:    time.Now().Add(30 * time.Minute), // Set expiration for 30 minutes
		CreatedAt:    time.Now(),
		SessionData:  []string{"data1", "data2"}, // Replace with actual session data
	}

	err := m.Repo.CreateSessionMysql(session)
	if err != nil {
		return Session{}, err
	}
	return session, nil
}

// GetSSOSession retrieves an SSO session by its ID
func (m *AuthManager) GetSSOSession(sessionID int64) (Session, error) {
	session, err := m.Repo.GetSessionMysql(sessionID)
	if err != nil {
		return Session{}, err
	}
	return session, nil
}

// UpdateSSOSession updates an existing SSO session
func (m *AuthManager) UpdateSSOSession(session Session) error {
	return m.Repo.UpdateSessionMysql(session)
}

// DeleteSSOSession removes an SSO session by ID
func (m *AuthManager) DeleteSSOSession(sessionID int64) error {
	return m.Repo.DeleteSSOSession(sessionID)
}

// MFA Functions

// CreateMFAMethod adds a new MFA method for a user
func (m *AuthManager) CreateMFAMethod(userID int64, method MFAMethod) error {
	// Assign the UserID to the method before creating it
	method.UserID = userID

	// Call the repository function to add the MFA method and handle the result
	_, err := m.Repo.CreateMFAMethod(&method)
	if err != nil {
		return err
	}

	return nil
}

// GetMFAMethod retrieves an MFA method by its ID
func (m *AuthManager) GetMFAMethod(methodID int64) (MFAMethod, error) {
	method, err := m.Repo.GetMFAMethodByID(methodID)
	if err != nil {
		return MFAMethod{}, err
	}
	return *method, nil // Dereference the pointer to return a value
}

// UpdateMFAMethod updates an existing MFA method
func (m *AuthManager) UpdateMFAMethod(method MFAMethod) error {
	return m.Repo.UpdateMFAMethod(&method)
}

// DeleteMFAMethod removes an MFA method by ID
func (m *AuthManager) DeleteMFAMethod(methodID int64) error {
	return m.Repo.DeleteMFAMethod(methodID)
}

// Biometric Functions
// CreateBiometric adds a new biometric record for a user.
func (m *AuthManager) CreateBiometric(userID int64, biometric Biometric) error {
	// Assign the user ID to the biometric object
	biometric.UserID = userID

	// Call the repository function with the complete biometric object
	_, err := m.Repo.CreateBiometric(&biometric)
	return err
}

// GetBiometric retrieves a biometric record by user ID.
func (m *AuthManager) GetBiometric(userID int64) (*Biometric, error) {
	// Call the repository function to get the biometric record
	return m.Repo.GetBiometricByUserID(userID)
}

// UpdateBiometric updates an existing biometric record and returns the updated record
func (m *AuthManager) UpdateBiometric(biometric *Biometric) (*Biometric, error) {
	return m.Repo.UpdateBiometric(biometric)
}

// DeleteBiometric removes a biometric record by user ID
func (m *AuthManager) DeleteBiometric(userID int64) error {
	return m.Repo.DeleteBiometric(userID)
}

// CreateSession creates a new session for a user
// CreateSession creates a new session for a user with detailed session data
func (m *AuthManager) CreateSessionManager(userID int64, sessionToken string, sessionData SessionData) (Session, error) {
	if sessionToken == "" {
		return Session{}, errors.New("session token cannot be empty")
	}
	sessionDataSlice := []string{sessionData.Key, sessionData.Value}
	session := Session{
		UserID:       userID,
		SessionToken: sessionToken,
		IsActive:     true,
		LastAccessed: time.Now(),
		ExpiresAt:    time.Now().Add(30 * time.Minute), // Example expiration time
		CreatedAt:    time.Now(),
		SessionData:  sessionDataSlice, // Use single value if that's the intended structure
	}

	// Ensure repository handles session correctly (e.g., as pointer or value)
	err := m.Repo.CreateSessionMysql(session) // No pointer here
	if err != nil {
		return Session{}, err
	}
	return session, nil
}

// GetSession retrieves a session by its ID
func (m *AuthManager) GetSession(sessionID int64) (Session, error) {
	if sessionID <= 0 {
		return Session{}, errors.New("invalid session ID")
	}

	session, err := m.Repo.GetSessionMysql(sessionID)
	if err != nil {
		return Session{}, err
	}
	return session, nil
}

// UpdateSession updates an existing session
func (m *AuthManager) UpdateSession(session Session) error {
	if session.ID <= 0 {
		return errors.New("invalid session ID")
	}

	session.LastAccessed = time.Now() // Update last accessed time
	err := m.Repo.UpdateSessionMysql(session)
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

	err := m.Repo.DeleteSessionMysql(sessionID)
	if err != nil {
		return err
	}
	return nil
}

// GetSessionsByUserID retrieves all sessions for a specific user
func (m *AuthManager) GetSessionsByUserID(userID int64) ([]Session, error) {
	if userID <= 0 {
		return nil, errors.New("invalid user ID")
	}

	sessions, err := m.Repo.GetSessionsByUserIDMysql(userID)
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
	err = m.Repo.UpdateSessionMysql(session)
	if err != nil {
		return err
	}

	return nil
}
