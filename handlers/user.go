package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go-dynamo-demo/storage"
)

// Handlers handles HTTP requests related to users
type Handlers struct {
	repo      *storage.Client
	jwtSecret []byte
}

// NewHandler creates a new Handlers
func NewHandler(repo *storage.Client, jwtSecret string) *Handlers {
	return &Handlers{
		repo:      repo,
		jwtSecret: []byte(jwtSecret),
	}
}

// CreateUser handles the creation of a new user
func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user storage.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate a new UUID for the user
	user.ID = uuid.New().String()

	// Create the user using the repository
	err = h.repo.CreateUser(r.Context(), &user)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Remove password before sending response
	user.Password = ""

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	// Token string `json:"token"` Currently sent as cookie
	Message string `json:"message"`
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Use the repository to authenticate the user
	user, err := h.repo.Login(r.Context(), storage.LoginCredentials{
		Email:    loginReq.Email,
		Password: loginReq.Password,
	})
	if err != nil {
		if errors.Is(err, storage.ErrInvalidCredentials) {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Generate JWT token, everyone is an Admin!
	// TODO: stateless authentication, need to disable credentials before expiry?
	tokenString, err := GenerateToken(user.ID, []Role{RoleAdmin}, h.jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Set the token as an HTTP-only cookie
	// HTTP is of course only for demo'ing
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		HttpOnly: true,
		Secure:   true, // Set to true if using HTTPS
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   3600, // 1 hour
		Expires:  time.Now().Add(24 * time.Hour),
	})

	// Prepare and send the response
	response := LoginResponse{
		Message: "Login successful",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetUser handles getting a user
func (h *Handlers) GetUser(w http.ResponseWriter, r *http.Request) {
	// Extract the user ID from the URL parameters
	userID := chi.URLParam(r, "id")

	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Use the repository to fetch the user
	user, err := h.repo.GetUser(r.Context(), userID)
	if err != nil {
		// Check for specific errors
		if errors.Is(err, storage.ErrUserNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Remove sensitive information before sending the response
	user.Password = ""

	// Send the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (h *Handlers) GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.repo.GetUsers(r.Context())
	if err != nil {
		log.Println(err)
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// UpdateUser handles updating a user
func (h *Handlers) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	var updatedUser storage.User
	if err := json.NewDecoder(r.Body).Decode(&updatedUser); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Ensure the ID in the URL matches the ID in the request body
	if updatedUser.ID != userID {
		http.Error(w, "User ID in URL does not match ID in request body", http.StatusBadRequest)
		return
	}

	// Use the repository to update the user
	err := h.repo.UpdateUser(r.Context(), &updatedUser)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrUserNotFound):
			http.Error(w, "User not found", http.StatusNotFound)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Remove sensitive information before sending the response
	updatedUser.Password = ""

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedUser)
}

// DeleteUser handles deleting a user
func (h *Handlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Use the repository to delete the user
	err := h.repo.DeleteUser(r.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrUserNotFound):
			http.Error(w, "User not found", http.StatusNotFound)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
