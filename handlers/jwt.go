package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleCustomer Role = "customer"
)

type Claims struct {
	UserID string `json:"user_id"`
	Roles  []Role `json:"roles"`
	jwt.RegisteredClaims
}

const MinSecretLength = 2 // Should be >= 32 for production

func GenerateToken(userID string, roles []Role, jwtSecret []byte) (string, error) {
	if len(jwtSecret) < MinSecretLength {
		return "", fmt.Errorf("jwt secret must be at least %d bytes long", MinSecretLength)
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: userID,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// RoleAuthMiddleware checks that the required role is present in the JWT claims to access
// the protected handler
func (h *Handlers) RoleAuthMiddleware(requiredRoles ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())

			for _, requiredRole := range requiredRoles {
				if slices.Contains(claims.Roles, requiredRole) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}

type claimKey struct{}

func ClaimsFromContext(ctx context.Context) *Claims {
	claims, ok := ctx.Value(claimKey{}).(*Claims)
	if !ok {
		// TODO: Handle this?
		panic("no claims found")
	}
	return claims
}

func (h *Handlers) JWTValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenString string

		// Check for Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			bearerToken := strings.Split(authHeader, " ")
			if len(bearerToken) == 2 {
				tokenString = bearerToken[1]
			}
		}

		// If no Authorization header, check for cookie
		if tokenString == "" {
			cookie, err := r.Cookie("token")
			if err == nil {
				tokenString = cookie.Value
			}
		}

		// If no token found in either place, return unauthorized
		if tokenString == "" {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return h.jwtSecret, nil
		})

		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Println("claims:", claims, reflect.TypeOf(token.Claims))
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		roles, err := ConvertToRoles(claims["roles"])
		if err != nil {
			http.Error(w, "Invalid roles in token", http.StatusUnauthorized)
			return
		}

		// Add claims to the request context
		ctx := context.WithValue(r.Context(), claimKey{}, &Claims{
			UserID: claims["user_id"].(string),
			Roles:  roles,
		})

		// Call the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ConvertToRoles is required since we have a JSON interface slice
// that needs to be a Role slice. TODO: validate the roles
func ConvertToRoles(rolesInterface interface{}) ([]Role, error) {
	rolesSlice, ok := rolesInterface.([]interface{})
	if !ok {
		return nil, fmt.Errorf("roles claim is not a slice")
	}

	roles := make([]Role, len(rolesSlice))
	for i, r := range rolesSlice {
		roleStr, ok := r.(string)
		if !ok {
			return nil, fmt.Errorf("role at index %d is not a string", i)
		}
		roles[i] = Role(roleStr)
	}

	return roles, nil
}
