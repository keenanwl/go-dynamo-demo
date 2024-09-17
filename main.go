package main

import (
	"context"
	"github.com/go-chi/chi/v5/middleware"
	"go-dynamo-demo/handlers"
	"go-dynamo-demo/storage"
	"go-dynamo-demo/storage/dynamo"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func initRepository() *storage.Client {
	svc := setupDynamoDB()
	return dynamo.NewClient(svc, tableName)
}

func main() {

	repo := initRepository()
	seedUsers(repo)

	h := handlers.NewHandler(repo, "some-secret-that-should-be-provided-by-config")

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(handlers.WithDB(repo))

	// Public routes
	r.Group(func(r chi.Router) {
		r.Post("/api/login", h.Login)
		// For sign-up
		r.Post("/api/users", h.CreateUser)
	})

	// Protected routes
	r.Route("/api/users", func(r chi.Router) {
		r.Use(h.JWTValidationMiddleware)
		r.Use(h.RoleAuthMiddleware("admin"))
		r.Get("/", h.GetUsers) // List all users

		// Single user endpoints
		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", h.GetUser)       // Get a specific user
			r.Put("/", h.UpdateUser)    // Update a user
			r.Delete("/", h.DeleteUser) // Delete a user
		})
	})

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// TODO: Just demo data, not intended for production
func seedUsers(repo *storage.Client) {
	err := repo.CreateUser(context.Background(), &storage.User{
		ID:       "", // Generated
		Username: "klinsly@gmail.com",
		Email:    "klinsly@gmail.com",
		Password: "somepass",
	})
	if err != nil {
		panic(err)
	}

	err = repo.CreateUser(context.Background(), &storage.User{
		ID:       "", // Generated
		Username: "klinsly1@gmail.com",
		Email:    "klinsly1@gmail.com",
		Password: "somepass",
	})
	if err != nil {
		panic(err)
	}

	err = repo.CreateUser(context.Background(), &storage.User{
		ID:       "", // Generated
		Username: "klinsly2@gmail.com",
		Email:    "klinsly2@gmail.com",
		Password: "somepass",
	})
	if err != nil {
		panic(err)
	}
	log.Println("created seed data")
}
