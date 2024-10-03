package main

import (
	"context"
	"embed"
	"fmt"
	"github.com/go-chi/chi/v5/middleware"
	"go-dynamo-demo/handlers"
	"go-dynamo-demo/storage"
	"go-dynamo-demo/storage/dynamo"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
)

func initRepository() *storage.Client {
	svc := setupDynamoDB()
	return dynamo.NewClient(svc, tableName)
}

// Requires that frontend is built (yarn run build) before building the backend
//
//go:embed frontend/out/**
var staticFrontendFiles embed.FS

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

	// Serve static files and handle SPA routing
	r.Get("/*", fsHandler(removeFsPrefix(staticFrontendFiles, "frontend/out"), "/"))

	log.Println("Embedded NextJS static files")
	walkEmbedFS()
	// TODO: handle logs
	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func walkEmbedFS() error {
	return fs.WalkDir(staticFrontendFiles, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			fmt.Println("File:", p)
		}
		return nil
	})
}

func removeFsPrefix(embedded embed.FS, prefix string) fs.FS {
	output, err := fs.Sub(embedded, prefix)
	if err != nil {
		panic(fmt.Errorf("failed getting the sub tree for the site files: %w", err))
	}
	return output
}

// urlPrefix removes the URL.Path so Path does not have to
// match the embedded FS path
func fsHandler(embedded fs.FS, urlPrefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		baseTrim := strings.TrimPrefix(path.Clean(r.URL.Path), urlPrefix)
		f, err := embedded.Open(baseTrim)
		if err == nil {
			defer f.Close()
		}

		fmt.Println(baseTrim, err)
		if os.IsNotExist(err) {
			r.URL.Path = "/"
		} else {
			r.URL.Path = baseTrim
		}
		http.FileServer(http.FS(embedded)).ServeHTTP(w, r)
	}
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
