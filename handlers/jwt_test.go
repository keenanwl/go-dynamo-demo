package handlers

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGenerateToken(t *testing.T) {
	jwtSecret := []byte("test_secret")

	tests := []struct {
		name        string
		userID      string
		roles       []Role
		expectError bool
	}{
		{
			name:        "Valid token - Admin role",
			userID:      "user123",
			roles:       []Role{RoleAdmin},
			expectError: false,
		},
		{
			name:        "Valid token - Customer role",
			userID:      "user456",
			roles:       []Role{RoleCustomer},
			expectError: false,
		},
		{
			name:        "Valid token - Multiple roles",
			userID:      "user789",
			roles:       []Role{RoleAdmin, RoleCustomer},
			expectError: false,
		},
		{
			name:        "Valid token - No roles",
			userID:      "user101",
			roles:       []Role{},
			expectError: false,
		},
		{
			name:        "Empty userID",
			userID:      "",
			roles:       []Role{RoleAdmin},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(tt.userID, tt.roles, jwtSecret)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)

				// Verify the token
				parsedToken, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
					return jwtSecret, nil
				})

				assert.NoError(t, err)
				assert.True(t, parsedToken.Valid)

				claims, ok := parsedToken.Claims.(*Claims)
				assert.True(t, ok)

				assert.Equal(t, tt.userID, claims.UserID)
				assert.Equal(t, tt.roles, claims.Roles)

				// Check expiration time
				assert.True(t, claims.ExpiresAt.After(time.Now()))
				assert.True(t, claims.ExpiresAt.Before(time.Now().Add(25*time.Hour)))
			}
		})
	}
}

func TestGenerateTokenSecretLength(t *testing.T) {
	_, err := GenerateToken("user123", []Role{RoleAdmin}, []byte(""))
	assert.Error(t, err)

	shortSecret := []byte("1")
	userID := "user123"
	roles := []Role{RoleAdmin}

	_, err = GenerateToken(userID, roles, shortSecret)
	assert.Error(t, err)

	longEnoughSecret := []byte("thisisasecretlongerthan32bytes12345")
	token, err := GenerateToken(userID, roles, longEnoughSecret)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestGenerateTokenConsistency(t *testing.T) {
	jwtSecret := []byte("test_secret")
	userID := "user123"
	roles := []Role{RoleAdmin, RoleCustomer}

	token1, err1 := GenerateToken(userID, roles, jwtSecret)
	time.Sleep(1 * time.Second)
	token2, err2 := GenerateToken(userID, roles, jwtSecret)

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NotEqual(t, token1, token2, "Tokens should be different due to different expiration times")
}

func TestGenerateTokenPayload(t *testing.T) {
	jwtSecret := []byte("test_secret")
	userID := "user123"
	roles := []Role{RoleAdmin, RoleCustomer}

	token, err := GenerateToken(userID, roles, jwtSecret)
	assert.NoError(t, err)

	// Parse the token without verifying the signature
	parsedToken, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return nil, nil // We're not verifying the signature in this test
	})

	// Check if parsing was successful
	assert.NotNil(t, parsedToken)

	// Extract claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	// Check user ID
	assert.Equal(t, userID, claims["user_id"])

	// Check roles
	claimRoles, ok := claims["roles"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, claimRoles, len(roles))
	for i, role := range roles {
		assert.Equal(t, string(role), claimRoles[i])
	}

	// Check expiration time
	exp, ok := claims["exp"].(float64)
	assert.True(t, ok)
	assert.Greater(t, exp, float64(time.Now().Unix()))
	assert.Less(t, exp, float64(time.Now().Add(25*time.Hour).Unix()))
}

func TestJWTMiddleware(t *testing.T) {
	jwtSecret := []byte("test_secret")
	h := &Handlers{jwtSecret: jwtSecret}

	tests := []struct {
		name           string
		setupAuth      func(*http.Request)
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Valid JWT",
			setupAuth: func(r *http.Request) {
				token := jwt.New(jwt.SigningMethodHS256)
				tokenString, _ := token.SignedString(jwtSecret)
				r.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Missing Authorization Header",
			setupAuth:      func(r *http.Request) {},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Authorization header is required\n",
		},
		{
			name: "Invalid Authorization Header Format",
			setupAuth: func(r *http.Request) {
				r.Header.Set("Authorization", "InvalidFormat")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid token format\n",
		},
		{
			name: "Invalid JWT Signature",
			setupAuth: func(r *http.Request) {
				token := jwt.New(jwt.SigningMethodHS256)
				tokenString, _ := token.SignedString([]byte("wrong_secret"))
				r.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid token\n",
		},
		{
			name: "Expired JWT",
			setupAuth: func(r *http.Request) {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
				})
				tokenString, _ := token.SignedString(jwtSecret)
				r.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid token\n",
		},
		{
			name: "JWT with Invalid Signing Method",
			setupAuth: func(r *http.Request) {
				token := jwt.New(jwt.SigningMethodRS256)
				tokenString, _ := token.SignedString(jwtSecret)
				r.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid token\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/test", nil)
			assert.NoError(t, err)

			tt.setupAuth(req)

			rr := httptest.NewRecorder()
			handler := h.JWTValidationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code, "handler returned wrong status code")
			assert.Equal(t, tt.expectedBody, rr.Body.String(), "handler returned unexpected body")
		})
	}
}

func TestRoleAuthMiddleware(t *testing.T) {
	h := &Handlers{}

	tests := []struct {
		name           string
		requiredRoles  []Role
		userRoles      []Role
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Single role - Authorized",
			requiredRoles:  []Role{RoleAdmin},
			userRoles:      []Role{RoleAdmin},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Single role - Unauthorized",
			requiredRoles:  []Role{RoleAdmin},
			userRoles:      []Role{RoleCustomer},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden\n",
		},
		{
			name:           "Multiple required roles - One match",
			requiredRoles:  []Role{RoleAdmin, RoleCustomer},
			userRoles:      []Role{RoleCustomer},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Multiple required roles - No match",
			requiredRoles:  []Role{RoleAdmin, RoleCustomer},
			userRoles:      []Role{"InvalidRole"},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden\n",
		},
		{
			name:           "Multiple user roles - One match",
			requiredRoles:  []Role{RoleAdmin},
			userRoles:      []Role{RoleCustomer, RoleAdmin},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "No required roles",
			requiredRoles:  []Role{},
			userRoles:      []Role{RoleCustomer},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden\n",
		},
		{
			name:           "No user roles",
			requiredRoles:  []Role{RoleAdmin},
			userRoles:      []Role{},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden\n",
		},
		{
			name:           "Missing claims",
			requiredRoles:  []Role{RoleAdmin},
			userRoles:      nil,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Unauthorized\n",
		},
		{
			name:           "Case sensitivity - Lowercase required",
			requiredRoles:  []Role{"admin"},
			userRoles:      []Role{"Admin"},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden\n",
		},
		{
			name:           "Case sensitivity - Uppercase required",
			requiredRoles:  []Role{"ADMIN"},
			userRoles:      []Role{"admin"},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/test", nil)
			assert.NoError(t, err)

			if tt.userRoles != nil {
				ctx := context.WithValue(req.Context(), "claims", &Claims{Roles: tt.userRoles})
				req = req.WithContext(ctx)
			}

			rr := httptest.NewRecorder()

			handler := h.RoleAuthMiddleware(tt.requiredRoles...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code, "handler returned wrong status code")
			assert.Equal(t, tt.expectedBody, rr.Body.String(), "handler returned unexpected body")
		})
	}
}

func TestRoleAuthMiddlewarePerformance(t *testing.T) {
	h := &Handlers{}

	// Create a large number of roles
	manyRoles := make([]Role, 1000)
	for i := range manyRoles {
		manyRoles[i] = Role(fmt.Sprintf("role%d", i))
	}

	req, _ := http.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), "claims", &Claims{Roles: manyRoles})
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	handler := h.RoleAuthMiddleware("role999")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	start := time.Now()
	handler.ServeHTTP(rr, req)
	duration := time.Since(start)

	assert.Equal(t, http.StatusOK, rr.Code, "handler returned wrong status code")
	assert.Less(t, duration, 10*time.Millisecond, "handler took too long to process")
}
