package Authentication

import (
	"AuthenticationModel"
	"database/sql"
	"fmt"
	"time"
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
	query := `SELECT * FROM app_users WHERE user_id = ?`

	err := r.db.QueryRow(query, userID).Scan(
		&user.ID,
		&user.ParentID,
		&user.OrgID,
		&user.AddrID,
		&user.AccountNumber,
		&user.DistributorID,
		&user.PhoneNo,
		&user.EmailAddress,
		&user.SystemName,
		&user.Group,
		&user.PIN,
		&user.Password,
		&user.SecretKey,
		&user.APIAuthKey,
		&user.FirstNameEN,
		&user.FirstNameNtv,
		&user.LastNameEN,
		&user.LastNameNtv,
		&user.Type,
		&user.MultiCurrencyCrypto,
		&user.MultiCurrencyUSD,
		&user.MultiCurrencyGBP,
		&user.MultiCurrencyBDT,
		&user.MultiCurrencyINR,
		&user.MultiCurrencyEUR,
		&user.MultiCurrencyAED,
		&user.RegistrationDate,
		&user.Status,
		&user.DateOfBirth,
		&user.TermsCondition,
		&user.EmailVerification,
		&user.CreatedBy,
		&user.VerifiedBy,
		&user.ValidatedBy,
		&user.ApprovedBy,
		&user.ModifiedBy,
		&user.CreatedDate,
		&user.VerifiedDate,
		&user.ValidatedDate,
		&user.ApprovedDate,
		&user.ModifiedDate,
		&user.RoleID,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No user found
		}
		return nil, fmt.Errorf("error retrieving user: %v", err)
	}

	return user, nil
}

// AuthenticateUser checks the user credentials for Mobile and IoT.
func (r *UserRepository) AuthenticateUserMobile(PhoneNo int, PIN string) (*User, error) {
	user := &User{}

	// SQL query to select user details and match the phone number and hashed PIN
	query := `
		SELECT user_system_name, user_phone_no
		FROM app_users
		WHERE user_phone_no = ? 
		AND user_pin = SUBSTR(SHA2(?, 256), -8, 8)`

	// Execute the query with the provided UserPhoneNo and PIN (as hashed PIN)
	err := r.db.QueryRow(query, PhoneNo, PIN).Scan(
		&user.SystemName,
		&user.PhoneNo,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No user found
		}
		return nil, fmt.Errorf("error authenticating user: %v", err)
	}

	// Return the authenticated user
	return user, nil
}

// AuthenticateUser checks the user credentials for website and others.
func (r *UserRepository) AuthenticateUser(SystemName string, Password string) (*User, error) {
	user := &User{}

	// SQL query to select user details and match the phone number and hashed PIN
	query := `
		SELECT user_system_name, user_phone_no
		FROM app_users
		WHERE user_phone_no = ? 
		AND user_pin = SUBSTR(SHA2(?, 256), -10, 10)`

	// Execute the query with the provided UserPhoneNo and PIN (as hashed PIN)
	err := r.db.QueryRow(query, SystemName, Password).Scan(
		&user.SystemName,
		&user.Password,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No user found
		}
		return nil, fmt.Errorf("error authenticating user: %v", err)
	}

	// Return the authenticated user
	return user, nil
}

type AuthRepository struct {
	DB *sql.DB
}

// NewAuthRepository initializes a new instance of AuthRepository
func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{DB: db}
}

// CreateAuthToken inserts a new AuthToken into the database
func (repo *AuthRepository) CreateAuthToken(token AuthenticationModel.AuthToken) error {
	_, err := repo.DB.Exec("INSERT INTO auth_tokens (user_id, token, token_type, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		token.UserID, token.Token, token.TokenType, token.ExpiresAt, time.Now())
	return err
}

// GetAuthToken retrieves an AuthToken by ID
func (repo *AuthRepository) GetAuthToken(id int64) (AuthenticationModel.AuthToken, error) {
	token := AuthenticationModel.AuthToken{}
	err := repo.DB.QueryRow("SELECT id, user_id, token, token_type, expires_at, created_at FROM auth_tokens WHERE id = ?", id).
		Scan(&token.ID, &token.UserID, &token.Token, &token.TokenType, &token.ExpiresAt, &token.CreatedAt)
	return token, err
}

// UpdateAuthToken updates an existing AuthToken
func (repo *AuthRepository) UpdateAuthToken(token AuthenticationModel.AuthToken) error {
	_, err := repo.DB.Exec("UPDATE auth_tokens SET token = ?, token_type = ?, expires_at = ? WHERE id = ?",
		token.Token, token.TokenType, token.ExpiresAt, token.ID)
	return err
}

// DeleteAuthToken removes an AuthToken by ID
func (repo *AuthRepository) DeleteAuthToken(id int64) error {
	_, err := repo.DB.Exec("DELETE FROM auth_tokens WHERE id = ?", id)
	return err
}

// CreateApiKey inserts a new API Key
func (repo *AuthRepository) CreateApiKey(key AuthenticationModel.ApiKey) error {
	_, err := repo.DB.Exec("INSERT INTO api_keys (key, client_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
		key.Key, key.ClientID, time.Now(), key.ExpiresAt)
	return err
}

// GetApiKey retrieves an API Key by ID
func (repo *AuthRepository) GetApiKey(id int64) (AuthenticationModel.ApiKey, error) {
	key := AuthenticationModel.ApiKey{}
	err := repo.DB.QueryRow("SELECT id, key, client_id, created_at, expires_at FROM api_keys WHERE id = ?", id).
		Scan(&key.ID, &key.Key, &key.ClientID, &key.CreatedAt, &key.ExpiresAt)
	return key, err
}

// UpdateApiKey updates an existing API Key
func (repo *AuthRepository) UpdateApiKey(key AuthenticationModel.ApiKey) error {
	_, err := repo.DB.Exec("UPDATE api_keys SET key = ?, client_id = ?, expires_at = ? WHERE id = ?",
		key.Key, key.ClientID, key.ExpiresAt, key.ID)
	return err
}

// DeleteApiKey removes an API Key by ID
func (repo *AuthRepository) DeleteApiKey(id int64) error {
	_, err := repo.DB.Exec("DELETE FROM api_keys WHERE id = ?", id)
	return err
}

// CreateOAuthClient adds a new OAuthClient
func (repo *AuthRepository) CreateOAuthClient(client AuthenticationModel.OAuthClient) error {
	_, err := repo.DB.Exec("INSERT INTO oauth_clients (client_id, client_secret, redirect_uri, scope, grant_type) VALUES (?, ?, ?, ?, ?)",
		client.ClientID, client.ClientSecret, client.RedirectURI, client.Scope, client.GrantType)
	return err
}

// GetOAuthClient retrieves an OAuthClient by ID
func (repo *AuthRepository) GetOAuthClient(id int64) (AuthenticationModel.OAuthClient, error) {
	client := AuthenticationModel.OAuthClient{}
	err := repo.DB.QueryRow("SELECT id, client_id, client_secret, redirect_uri, scope, grant_type FROM oauth_clients WHERE id = ?", id).
		Scan(&client.ID, &client.ClientID, &client.ClientSecret, &client.RedirectURI, &client.Scope, &client.GrantType)
	return client, err
}

// UpdateOAuthClient updates an existing OAuthClient
func (repo *AuthRepository) UpdateOAuthClient(client AuthenticationModel.OAuthClient) error {
	_, err := repo.DB.Exec("UPDATE oauth_clients SET client_secret = ?, redirect_uri = ?, scope = ?, grant_type = ? WHERE id = ?",
		client.ClientSecret, client.RedirectURI, client.Scope, client.GrantType, client.ID)
	return err
}

// DeleteOAuthClient removes an OAuthClient by ID
func (repo *AuthRepository) DeleteOAuthClient(id int64) error {
	_, err := repo.DB.Exec("DELETE FROM oauth_clients WHERE id = ?", id)
	return err
}

// CreateSSOSession adds a new SSO Session
func (repo *AuthRepository) CreateSSOSession(ssession AuthenticationModel.SSOSession) error {
	_, err := repo.DB.Exec("INSERT INTO sso_sessions (user_id, session_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
		ssession.UserID, ssession.SessionID, ssession.ExpiresAt, time.Now())
	return err
}

// GetSSOSession retrieves an SSO Session by ID
func (repo *AuthRepository) GetSSOSession(id int64) (AuthenticationModel.SSOSession, error) {
	ssession := AuthenticationModel.SSOSession{}
	err := repo.DB.QueryRow("SELECT id, user_id, session_id, expires_at, created_at FROM sso_sessions WHERE id = ?", id).
		Scan(&ssession.ID, &ssession.UserID, &ssession.SessionID, &ssession.ExpiresAt, &ssession.CreatedAt)
	return ssession, err
}

// UpdateSSOSession updates an existing SSO Session
func (repo *AuthRepository) UpdateSSOSession(ssession AuthenticationModel.SSOSession) error {
	_, err := repo.DB.Exec("UPDATE sso_sessions SET session_id = ?, expires_at = ? WHERE id = ?",
		ssession.SessionID, ssession.ExpiresAt, ssession.ID)
	return err
}

// DeleteSSOSession removes an SSO Session by ID
func (repo *AuthRepository) DeleteSSOSession(id int64) error {
	_, err := repo.DB.Exec("DELETE FROM sso_sessions WHERE id = ?", id)
	return err
}

// CRUD for Session Management with mysql table
// CreateSession adds a new session
// CreateSession adds a new session
func (repo *AuthRepository) CreateSession(session AuthenticationModel.Session) error {
	_, err := repo.DB.Exec("INSERT INTO auth_sessions (user_id, session_token, is_active, last_accessed, expires_at, created_at, session_data) VALUES (?, ?, ?, ?, ?, ?, ?)",
		session.UserID, session.SessionToken, session.IsActive, session.LastAccessed, session.ExpiresAt, time.Now(), session.SessionData)
	return err
}

// GetSession retrieves a session by ID
func (repo *AuthRepository) GetSession(id int64) (AuthenticationModel.Session, error) {
	session := AuthenticationModel.Session{}
	err := repo.DB.QueryRow("SELECT id, user_id, session_token, is_active, last_accessed, expires_at, created_at, session_data FROM auth_sessions WHERE id = ?", id).
		Scan(&session.ID, &session.UserID, &session.SessionToken, &session.IsActive, &session.LastAccessed, &session.ExpiresAt, &session.CreatedAt, &session.SessionData)
	if err != nil {
		return session, err
	}
	return session, nil
}

// UpdateSession updates an existing session
func (repo *AuthRepository) UpdateSession(session AuthenticationModel.Session) error {
	_, err := repo.DB.Exec("UPDATE auth_sessions SET session_token = ?, is_active = ?, last_accessed = ?, expires_at = ?, session_data = ? WHERE id = ?",
		session.SessionToken, session.IsActive, session.LastAccessed, session.ExpiresAt, session.SessionData, session.ID)
	return err
}

// DeleteSession removes a session by ID
func (repo *AuthRepository) DeleteSession(id int64) error {
	_, err := repo.DB.Exec("DELETE FROM auth_sessions WHERE id = ?", id)
	return err
}

// GetSessionsByUserID retrieves all sessions for a specific user
func (repo *AuthRepository) GetSessionsByUserID(userID int64) ([]AuthenticationModel.Session, error) {
	rows, err := repo.DB.Query("SELECT id, user_id, session_token, is_active, last_accessed, expires_at, created_at, session_data FROM auth_sessions WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []AuthenticationModel.Session
	for rows.Next() {
		var session AuthenticationModel.Session
		if err := rows.Scan(&session.ID, &session.UserID, &session.SessionToken, &session.IsActive, &session.LastAccessed, &session.ExpiresAt, &session.CreatedAt, &session.SessionData); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

// Other tables like MFAMethod, PasswordAuth, Biometric, Session, RefreshToken, DeviceFingerprint,
// LoginAttempt, and AuthEventLog would follow the same pattern for CRUD operations.
