package storage

import (
	"context"
	"errors"
)

type LoginCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TODO: Consider keeping storage completely separate?
type User struct {
	ID       string `json:"id" dynamodbav:"id"`
	Username string `json:"username" dynamodbav:"username"`
	Email    string `json:"email" dynamodbav:"email"`
	Password string `json:"password,omitempty" dynamodbav:"password,omitempty"`
}

type Repository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUsers(ctx context.Context) ([]*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	Login(ctx context.Context, credentials LoginCredentials) (*User, error)
}

// ErrInvalidCredentials is returned when the login credentials are incorrect
var ErrInvalidCredentials = errors.New("invalid email or password")
var ErrUserNotFound = errors.New("user not found")

type Client struct {
	Repository
}
