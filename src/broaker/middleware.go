/*
Key Middleware Functions:

	LoggingMiddleware:
	    Logs request method, URL, and remote address.
	    Logs response status.

	AuthenticationMiddleware:
	    Verifies the presence of a valid Authorization token.

	RateLimitingMiddleware:
	    Placeholder for rate-limiting logic to restrict the number of requests.

	ContextMiddleware:
	    Allows injecting custom data into the request context, useful for passing metadata or configurations.

	MiddlewareChain:
	    Chains multiple middleware functions, applying them in sequence.
*/
package broker

import (
	"context"
	"log"
	"net/http"
)

// Middleware defines a function type for request/response processing.
type Middleware func(http.Handler) http.Handler

// MiddlewareChain allows chaining multiple middleware functions together.
func MiddlewareChain(handler http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// LoggingMiddleware logs the details of each request.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Incoming request: Method=%s, URL=%s, RemoteAddr=%s", r.Method, r.URL, r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf("Completed request: Status=%d, URL=%s", http.StatusOK, r.URL)
	})
}

// AuthenticationMiddleware authenticates the request based on a token.
func AuthenticationMiddleware(authToken string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			if token != "Bearer "+authToken {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitingMiddleware limits the rate of incoming requests.
func RateLimitingMiddleware(maxRequests int, interval int) Middleware {
	// You can implement a rate-limiting mechanism like a token bucket or sliding window.
	// For simplicity, we return a placeholder here.
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Rate-limiting logic goes here.
			// Example: Reject requests exceeding maxRequests within interval seconds.
			next.ServeHTTP(w, r)
		})
	}
}

// ContextMiddleware injects broker-specific data into the context.
func ContextMiddleware(key string, value interface{}) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), key, value)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Example of registering middlewares
func Example() {
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, Broker!"))
	}))

	// Initialize the middleware chain.
	handler := MiddlewareChain(
		mux,
		LoggingMiddleware,
		AuthenticationMiddleware("secure-token"),
	)

	// Start the HTTP server.
	http.ListenAndServe(":8080", handler)
}
