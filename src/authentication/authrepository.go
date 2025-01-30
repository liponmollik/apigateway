package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// UserRepository provides access to user data.
type AuthRepository struct {
	DB  *sql.DB
	rdb *redis.Client
}

// NewUserRepository creates a new UserRepository.
func NewAuthRepository(db *sql.DB, rdb *redis.Client) *AuthRepository {
	return &AuthRepository{DB: db, rdb: rdb}
}
func generateSecureToken() string {
	return uuid.NewString()
}
func (repo *AuthRepository) VerifyPassword(u *User, password string) bool {
	if !isValidPassword(password) {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(*u.Password), []byte(password))
	return err == nil // Return true if the passwords match
}

// GetUserByID retrieves a user by their ID.
func (repo *AuthRepository) GetUserByID(userID int) (*User, error) {
	user := &User{}
	query := `SELECT * FROM app_users WHERE user_id = ?`

	err := repo.DB.QueryRow(query, userID).Scan(
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

// AuthenticateUserMobile checks the user credentials for Mobile and IoT.
func (repo *AuthRepository) getPhoneAndPIN(phoneNo string, PIN string) (*User, error) {
	query := `
		SELECT 
			user_phone_no,user_pin,address_id
		FROM app_users 
		WHERE user_phone_no = ? 
		AND user_pin = SUBSTR(SHA2(?, 256), -8, 8)`

	user := &User{}
	err := repo.DB.QueryRow(query, phoneNo, PIN, user.AddrID).Scan(
		&user.PIN,
		&user.PhoneNo,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No user found
		}
		return nil, fmt.Errorf("Phone or PIN might be wrong (PIN: %d): %v", phoneNo, err)
	}
	return user, nil
}

// AuthenticateUser validates credentials for system login.
func (repo *AuthRepository) getUserAndPassword(systemName, password string) (*rWeb, error) {
	query := `
        SELECT 
            user_system_name, user_password,user_api_autho_key
        FROM app_users 
        WHERE user_system_name = ? 
        AND user_password = SUBSTR(SHA2(?, 256), -10, 10)`

	rtnData := &rWeb{} // Use pointer to rWeb
	err := repo.DB.QueryRow(query, systemName, password).Scan(
		&rtnData.UserName,
		&rtnData.UserPassword,
		&rtnData.APIKey,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No user found
		}
		return nil, fmt.Errorf("failed to authenticate user (UserName: %s): %v", systemName, err)
	}

	// Generate a new secure session token if not already initialized
	if rtnData.SessionToken == "" {
		rtnData.SessionToken = generateSecureToken()
	}
	if rtnData.LoginMode == "" {
		rtnData.LoginMode = "web"
	}
	// Map rtnData to resData
	resData := &rWeb{
		UserName: rtnData.UserName,
		//UserPassword: rtnData.UserPassword,
		SessionToken: rtnData.SessionToken, // Use the generated secure token
		APIKey:       rtnData.APIKey,
		LoginMode:    rtnData.LoginMode, // Pass the login mode as a parameter
	}

	// Log or use resData as needed
	//fmt.Printf("Mapped Data: %+v\n", resData)
	return resData, nil
}

// Get Account and PIN for the case of IOT.
func (repo *AuthRepository) getAccountAndPIN(phoneNo string, PIN string) (*User, error) {
	query := `
		SELECT 
			account_no,user_pin,address_id
		FROM app_users 
		WHERE account_no = ? 
		AND user_pin = SUBSTR(SHA2(?, 256), -8, 8)`

	user := &User{}
	err := repo.DB.QueryRow(query, phoneNo, PIN, user.AddrID).Scan(
		&user.PIN,
		&user.PhoneNo,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No user found
		}
		return nil, fmt.Errorf("failed to authenticate user (phone: %d): %v", phoneNo, err)
	}
	return user, nil
}

// Get Address and PIN for the case of IOT.
func (repo *AuthRepository) getAccAddressAndPIN(phoneNo int, PIN string) (*User, error) {
	query := `
		SELECT 
			address_id,user_pin
		FROM app_users 
		WHERE address_id = ? 
		AND user_pin = SUBSTR(SHA2(?, 256), -8, 8)`

	user := &User{}
	err := repo.DB.QueryRow(query, phoneNo, PIN, user.AddrID).Scan(
		&user.PIN,
		&user.PhoneNo,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No user found
		}
		return nil, fmt.Errorf("failed to authenticate user (phone: %d): %v", phoneNo, err)
	}
	return user, nil
}

// CreateAuthToken inserts a new AuthToken into the database
func (repo *AuthRepository) CreateAuthToken(token AuthToken) error {

	query := "INSERT INTO auth_tokens (user_id, token, token_type, expires_at, created_at) VALUES (?, ?, ?, ?, ?)"

	_, err := repo.DB.Exec(query, token.UserID, token.Token, token.TokenType, token.ExpiresAt, time.Now())
	return err
}

// GetAuthToken retrieves an AuthToken by ID
func (repo *AuthRepository) GetAuthToken(id int64) (AuthToken, error) {
	token := AuthToken{}
	err := repo.DB.QueryRow("SELECT id, user_id, token, token_type, expires_at, created_at FROM auth_tokens WHERE id = ?", id).
		Scan(&token.ID, &token.UserID, &token.Token, &token.TokenType, &token.ExpiresAt, &token.CreatedAt)
	return token, err
}

// UpdateAuthToken updates an existing AuthToken
func (repo *AuthRepository) UpdateAuthToken(token AuthToken) error {
	query := "UPDATE auth_tokens SET token = ?, token_type = ?, expires_at = ? WHERE id = ?"
	_, err := repo.DB.Exec(query, token.Token, token.TokenType, token.ExpiresAt, token.ID)
	return err
}

// DeleteAuthToken removes an AuthToken by ID
func (repo *AuthRepository) DeleteAuthToken(id int64) error {
	query := "DELETE FROM auth_tokens WHERE id = ?"
	_, err := repo.DB.Exec(query, id)
	return err
}

// GetAuthTokenByToken retrieves an authentication token from the database by its token
func (repo *AuthRepository) GetAuthTokenByToken(token string) (*AuthToken, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}

	query := "SELECT token, user_id, expires_at FROM auth_tokens WHERE token = ?"
	row := repo.DB.QueryRow(query, token)

	var authToken AuthToken
	err := row.Scan(&authToken.Token, &authToken.UserID, &authToken.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("auth token not found")
		}
		return nil, err
	}

	return &authToken, nil
}

// CreateApiKey inserts a new API Key
func (repo *AuthRepository) CreateApiKey(key ApiKey) error {
	query := "INSERT INTO api_keys (key, client_id, created_at, expires_at) VALUES (?, ?, ?, ?)"
	_, err := repo.DB.Exec(query, key.Key, key.ClientID, time.Now(), key.ExpiresAt)
	return err
}

// GetApiKey retrieves an API Key by ID
func (repo *AuthRepository) GetApiKey(id int64) (ApiKey, error) {
	key := ApiKey{}
	query := "SELECT id, key, client_id, created_at, expires_at FROM api_keys WHERE id = ?"
	err := repo.DB.QueryRow(query, id).
		Scan(&key.ID, &key.Key, &key.ClientID, &key.CreatedAt, &key.ExpiresAt)
	return key, err
}

// UpdateApiKey updates an existing API Key
func (repo *AuthRepository) UpdateApiKey(key ApiKey) error {
	query := "UPDATE api_keys SET key = ?, client_id = ?, expires_at = ? WHERE id = ?"
	_, err := repo.DB.Exec(query, key.Key, key.ClientID, key.ExpiresAt, key.ID)
	return err
}

// DeleteApiKey removes an API Key by ID
func (repo *AuthRepository) DeleteApiKey(id int64) error {
	query := "DELETE FROM api_keys WHERE id = ?"
	_, err := repo.DB.Exec(query, id)
	return err
}

// CreateOAuthClient adds a new OAuthClient
func (repo *AuthRepository) CreateOAuthClient(client OAuthClient) error {
	query := "INSERT INTO oauth_clients (client_id, client_secret, redirect_uri, scope, grant_type) VALUES (?, ?, ?, ?, ?)"
	_, err := repo.DB.Exec(query, client.ClientID, client.ClientSecret, client.RedirectURI, client.Scope, client.GrantType)
	return err
}

// GetOAuthClient retrieves an OAuthClient by ID
func (repo *AuthRepository) GetOAuthClient(id int64) (OAuthClient, error) {
	client := OAuthClient{}
	query := "SELECT id, client_id, client_secret, redirect_uri, scope, grant_type FROM oauth_clients WHERE id = ?"
	err := repo.DB.QueryRow(query, id).
		Scan(&client.ID, &client.ClientID, &client.ClientSecret, &client.RedirectURI, &client.Scope, &client.GrantType)
	return client, err
}

// UpdateOAuthClient updates an existing OAuthClient
func (repo *AuthRepository) UpdateOAuthClient(client OAuthClient) error {
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
func (repo *AuthRepository) CreateSSOSession(ssession SSOSession) error {
	_, err := repo.DB.Exec("INSERT INTO sso_sessions (user_id, session_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
		ssession.UserID, ssession.SessionID, ssession.ExpiresAt, time.Now())
	return err
}

// GetSSOSession retrieves an SSO Session by ID
func (repo *AuthRepository) GetSSOSession(id int64) (SSOSession, error) {
	ssession := SSOSession{}
	err := repo.DB.QueryRow("SELECT id, user_id, session_id, expires_at, created_at FROM sso_sessions WHERE id = ?", id).
		Scan(&ssession.ID, &ssession.UserID, &ssession.SessionID, &ssession.ExpiresAt, &ssession.CreatedAt)
	return ssession, err
}

// UpdateSSOSession updates an existing SSO Session
func (repo *AuthRepository) UpdateSSOSession(ssession SSOSession) error {
	_, err := repo.DB.Exec("UPDATE sso_sessions SET session_id = ?, expires_at = ? WHERE id = ?",
		ssession.SessionID, ssession.ExpiresAt, ssession.ID)
	return err
}

// DeleteSSOSession removes an SSO Session by ID
func (repo *AuthRepository) DeleteSSOSession(id int64) error {
	_, err := repo.DB.Exec("DELETE FROM sso_sessions WHERE id = ?", id)
	return err
}

// CRUD for Session Management with redis table
// CreateSession adds a new session
func (repo *AuthRepository) CreateSessionMysql(session Session) error {
	_, err := repo.DB.Exec("INSERT INTO auth_sessions (user_id, session_token, is_active, last_accessed, expires_at, created_at, session_data) VALUES (?, ?, ?, ?, ?, ?, ?)",
		session.UserID, session.SessionToken, session.IsActive, session.LastAccessed, session.ExpiresAt, time.Now(), session.SessionData)
	return err
}

// GetSession retrieves a session by ID
func (repo *AuthRepository) GetSessionMysql(id int64) (Session, error) {
	session := Session{}
	err := repo.DB.QueryRow("SELECT id, user_id, session_token, is_active, last_accessed, expires_at, created_at, session_data FROM auth_sessions WHERE id = ?", id).
		Scan(&session.ID, &session.UserID, &session.SessionToken, &session.IsActive, &session.LastAccessed, &session.ExpiresAt, &session.CreatedAt, &session.SessionData)
	if err != nil {
		return session, err
	}
	return session, nil
}

// UpdateSession updates an existing session
func (repo *AuthRepository) UpdateSessionMysql(session Session) error {
	_, err := repo.DB.Exec("UPDATE auth_sessions SET session_token = ?, is_active = ?, last_accessed = ?, expires_at = ?, session_data = ? WHERE id = ?",
		session.SessionToken, session.IsActive, session.LastAccessed, session.ExpiresAt, session.SessionData, session.ID)
	return err
}

// DeleteSession removes a session by ID
func (repo *AuthRepository) DeleteSessionMysql(id int64) error {
	_, err := repo.DB.Exec("DELETE FROM auth_sessions WHERE id = ?", id)
	return err
}

// GetSessionsByUserID retrieves all sessions for a specific user
func (repo *AuthRepository) GetSessionsByUserIDMysql(userID int64) ([]Session, error) {
	// Query the database for all sessions for the given userID
	rows, err := repo.DB.Query("SELECT id, user_id, session_token, is_active, last_accessed, expires_at, created_at, session_data FROM auth_sessions WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Initialize a slice to hold the sessions
	var sessions []Session

	// Iterate over the rows and scan each session's data into the session struct
	for rows.Next() {
		var session Session
		if err := rows.Scan(&session.ID, &session.UserID, &session.SessionToken, &session.IsActive, &session.LastAccessed, &session.ExpiresAt, &session.CreatedAt, &session.SessionData); err != nil {
			return nil, err
		}
		// Append the session to the slice
		sessions = append(sessions, session)
	}

	// Check for any errors encountered during row iteration
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Return the slice of sessions
	return sessions, nil
}

// GetApiKeyByKey retrieves an API key record from the database using the provided key.
func (r *AuthRepository) GetApiKeyByKey(apiKey string) (*ApiKey, error) {
	var keyRecord ApiKey

	// Query the database for the API key
	query := "SELECT *FROM auth_api_keys WHERE api_key = ?"
	err := r.DB.QueryRow(query, apiKey).Scan(
		&keyRecord.ID,
		&keyRecord.Key,
		&keyRecord.ClientID,
		&keyRecord.Status,
		&keyRecord.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No matching API key found
		}
		return nil, fmt.Errorf("failed to query API key: %w", err)
	}

	return &keyRecord, nil
}

// GetOAuthClientByClientID retrieves the OAuth client information by clientID from the database.
func (repo *AuthRepository) GetOAuthClientByClientID(clientID string) (*OAuthClient, error) {
	// Define a variable to hold the result
	var oauthClient OAuthClient

	// Query the database for the OAuth client with the given clientID
	query := "SELECT * FROM oauth_clients WHERE client_id = ? LIMIT 1"

	// Execute the query
	row := repo.DB.QueryRow(query, clientID)

	// Scan the result into the oauthClient struct
	err := row.Scan(
		&oauthClient.ID,
		&oauthClient.ClientID,
		&oauthClient.ClientSecret,
		&oauthClient.RedirectURI,
		&oauthClient.Scope,
	)

	// Handle errors from querying or scanning
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("OAuth client not found")
		}
		return nil, fmt.Errorf("Error fetching OAuth client: %v", err)
	}

	// Return the retrieved OAuth client and nil for error
	return &oauthClient, nil
}

// CreateMFAMethod inserts a new MFA method into the database.
func (repo *AuthRepository) CreateMFAMethod(method *MFAMethod) (*MFAMethod, error) {
	// Define the query to insert the new MFA method into the database
	query := `
        INSERT INTO mfa_methods (user_id, method, destination)
        VALUES (?, ?, ?)
        RETURNING id, user_id, method, destination, created_at, updated_at
    `

	// Declare a variable to hold the result
	var newMethod MFAMethod

	// Execute the query and scan the returned values into the newMethod struct
	err := repo.DB.QueryRow(query, method.UserID, method.Method, method.Destination).Scan(
		&newMethod.ID,
		&newMethod.UserID,
		&newMethod.Method,
		&newMethod.Destination,
	)

	// Handle any errors during insertion
	if err != nil {
		return nil, fmt.Errorf("failed to create MFA method: %v", err)
	}

	// Return the created MFA method
	return &newMethod, nil
}

// GetMFAMethodByID retrieves an MFA method by its ID from the database.
func (repo *AuthRepository) GetMFAMethodByID(methodID int64) (*MFAMethod, error) {
	// Define the query to select the MFA method by its ID
	query := `
        SELECT id, user_id, method, destination, created_at, updated_at
        FROM mfa_methods
        WHERE id = ?
    `

	// Declare a variable to hold the result
	var method MFAMethod

	// Execute the query and scan the returned values into the method struct
	err := repo.DB.QueryRow(query, methodID).Scan(
		&method.ID,
		&method.UserID,
		&method.Method,
		&method.Destination,
	)

	// If no rows were returned or there's an error
	if err != nil {
		if err == sql.ErrNoRows {
			// Return nil if no matching MFA method was found
			return nil, fmt.Errorf("MFA method with ID %d not found", methodID)
		}
		return nil, fmt.Errorf("failed to get MFA method: %v", err)
	}

	// Return the found MFA method
	return &method, nil
}

// UpdateMFAMethod updates the details of an existing MFA method in the database.
func (repo *AuthRepository) UpdateMFAMethod(method *MFAMethod) error {
	// Define the query to update the MFA method by its ID
	query := `
        UPDATE mfa_methods
        SET method = ?, destination = ?, updated_at = NOW()
        WHERE id = ?
    `

	// Execute the query with the provided method details
	result, err := repo.DB.Exec(query, method.Method, method.Destination, method.ID)
	if err != nil {
		return fmt.Errorf("failed to update MFA method: %v", err)
	}

	// Check if any row was affected by the update
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %v", err)
	}

	// If no rows were affected, the method ID was not found
	if rowsAffected == 0 {
		return fmt.Errorf("MFA method with ID %d not found", method.ID)
	}

	// Return nil if the update was successful
	return nil
}

// DeleteMFAMethod removes an MFA method from the database by its ID.
func (repo *AuthRepository) DeleteMFAMethod(methodID int64) error {
	result, err := repo.DB.Exec("DELETE FROM mfa_methods WHERE id = ?", methodID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no MFA method found with ID %d", methodID)
	}

	return nil
}

// CreateBiometric inserts a new biometric record for a user.
func (repo *AuthRepository) CreateBiometric(biometric *Biometric) (*Biometric, error) {
	query := "INSERT INTO auth_biometrics (user_id, method, data) VALUES (?, ?, ?)"
	result, err := repo.DB.Exec(query, biometric.UserID, biometric.Method, biometric.Data)
	if err != nil {
		return nil, err
	}

	biometricID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	biometric.ID = biometricID
	return biometric, nil
}

// GetBiometricByUserID retrieves the biometric record for a user by their ID.
func (repo *AuthRepository) GetBiometricByUserID(userID int64) (*Biometric, error) {
	row := repo.DB.QueryRow("SELECT id, user_id, method, data FROM auth_biometrics WHERE user_id = ?", userID)

	var biometric Biometric
	if err := row.Scan(&biometric.ID, &biometric.UserID, &biometric.Method, &biometric.Data); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no biometric data found for user %d", userID)
		}
		return nil, err
	}

	return &biometric, nil
}

// Repository function for updating a biometric record and returning the updated record
func (repo *AuthRepository) UpdateBiometric(biometric *Biometric) (*Biometric, error) {
	query := `
        UPDATE biometrics 
        SET biometric_hash = ?, updated_at = NOW() 
        WHERE id = ? AND user_id = ?
        RETURNING id, user_id, biometric_hash, created_at, updated_at
    `
	var updatedBiometric Biometric
	err := repo.DB.QueryRow(query, biometric.BiometricHash, biometric.ID, biometric.UserID).Scan(
		&updatedBiometric.ID,
		&updatedBiometric.UserID,
		&updatedBiometric.BiometricHash,
		&updatedBiometric.CreatedAt,
		&updatedBiometric.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &updatedBiometric, nil
}

// DeleteBiometric removes biometric data for a user by their ID.
func (repo *AuthRepository) DeleteBiometric(userID int64) error {
	result, err := repo.DB.Exec("DELETE FROM auth_biometrics WHERE user_id = ?", userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no biometric data found for user %d to delete", userID)
	}

	return nil
}

// Other tables like MFAMethod, PasswordAuth, Biometric, Session, RefreshToken, DeviceFingerprint,
// LoginAttempt, and AuthEventLog would follow the same pattern for CRUD operations.
