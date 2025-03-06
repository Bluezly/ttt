package main

import (
	"log"
	"net/http"
)

func main() {
	// Initialize bot manager
	botManager := NewBotManager()

	// Create HTTP mux for routing
	mux := http.NewServeMux()

	// Register API handlers
	registerAPIHandlers(mux, botManager)

	// Serve static files
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	// Enable CORS and start server
	handler := enableCORS(mux)

	log.Println("Starting Discord Bot Manager on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

// Enable CORS middleware
func enableCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-ID")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		handler.ServeHTTP(w, r)
	})
}