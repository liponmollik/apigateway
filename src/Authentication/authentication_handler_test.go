// AuthenticationHandler/authentication_handler_test.go
package Authentication

import (
	"AuthenticationModel"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	// Ensure this is the correct import path
	// Ensure this is the correct import path

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockUserService is a mock implementation of the UserService for testing
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) Authenticate(userPin int, password string) (*AuthenticationModel.User, error) {
	args := m.Called(userPin, password)
	return args.Get(0).(*AuthenticationModel.User), args.Error(1)
}

func (m *MockUserService) CreateSession(userID int, password string, sessionData AuthenticationModel.SessionData) (*AuthenticationMode.Session, error) {
	args := m.Called(userID, password, sessionData)
	return args.Get(0).(*AuthenticationModel.Session), args.Error(1)
}

func TestAuthHandler_AuthHandler_Success(t *testing.T) {
	mockService := new(MockUserService)
	user := &AuthenticationModel.User{
		ID:            1,
		ParentID:      100,
		OrgID:         200,
		AddrID:        300,
		AccountNumber: "123456789",
		DistributorID: "D123",
		EmailAddress:  "user@example.com",
		SystemName:    "System A",
	}
	session := &AuthenticationModel.Session{SessionToken: "valid_token", ExpiresAt: "2024-12-31T23:59:59Z"}

	mockService.On("Authenticate", 123456, "password").Return(user, nil)
	mockService.On("CreateSession", user.ID, "password", mock.Anything).Return(session, nil)

	handler := NewUserHandler(mockService)

	reqBody := map[string]interface{}{
		"user_pin": 123456,
		"password": "password",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.AuthHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Equal(t, "valid_token", resp["session_token"])
	assert.Equal(t, "2024-12-31T23:59:59Z", resp["expires_at"])
}

func TestAuthHandler_AuthHandler_InvalidCredentials(t *testing.T) {
	mockService := new(MockUserService)

	mockService.On("Authenticate", 123456, "wrong_password").Return(nil, nil)

	handler := NewUserHandler(mockService)

	reqBody := map[string]interface{}{
		"user_pin": 123456,
		"password": "wrong_password",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.AuthHandler(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestAuthHandler_TokenAuthenticationHandler(t *testing.T) {
	mockManager := new(MockAuthManager)
	handler := NewAuthHandler(mockManager)

	req := httptest.NewRequest(http.MethodGet, "/token_auth", nil)
	req.Header.Set("Authorization", "valid_token")
	rr := httptest.NewRecorder()

	mockManager.On("ValidateToken", "valid_token").Return(true, nil)

	handler.TokenAuthenticationHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "Token is valid", rr.Body.String())
}

func TestAuthHandler_APIKeyHandler(t *testing.T) {
	mockManager := new(MockAuthManager)
	handler := NewAuthHandler(mockManager)

	req := httptest.NewRequest(http.MethodGet, "/apikey_auth", nil)
	req.Header.Set("X-API-Key", "valid_api_key")
	rr := httptest.NewRecorder()

	mockManager.On("ValidateAPIKey", "valid_api_key").Return(true, nil)

	handler.APIKeyHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "API key is valid", rr.Body.String())
}

// Add more tests for OAuthHandler and other functionalities as needed
