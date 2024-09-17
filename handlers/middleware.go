package handlers

import (
	"context"
	"github.com/gorilla/mux"
	"go-dynamo-demo/storage"
	"log"
	"net/http"
	"time"
)

// Reduce probability of collision
type dbKey struct{}

// WithDB adds middleware so each request has the DB context
func WithDB(db *storage.Client) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), dbKey{}, db)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromCtx gets the DB from context
// This can of course panic if not available, but that should
// be caught in CI, allowing us to prioritize the DX ergonomics.
func FromCtx(ctx context.Context) *storage.Client {
	return ctx.Value(dbKey{}).(*storage.Client)
}

func DebugMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Log basic request details
		log.Printf("Started %s %s", r.Method, r.URL.Path)

		// Log request headers
		for name, headers := range r.Header {
			for _, h := range headers {
				log.Printf("Header %v: %v", name, h)
			}
		}

		// Create a custom response writer to capture the status code
		wrappedWriter := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call the next handler
		next.ServeHTTP(wrappedWriter, r)

		// Log the response details
		duration := time.Since(start)
		log.Printf("Completed %s %s with status %d in %v", r.Method, r.URL.Path, wrappedWriter.statusCode, duration)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}
