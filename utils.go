package main

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"net/http"
)

// Generate random string for session IDs and other uses
func generateRandomName(prefix string, length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return prefix + hex.EncodeToString(bytes)
}

// Enable CORS for API endpoints
func enableCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-ID")
}

// Get random user agent for API requests
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
	}
	
	b := make([]byte, 1)
	rand.Read(b)
	return userAgents[int(b[0])%len(userAgents)]
}

// Min function for float64 values
func min(a, b float64) float64 {
	return math.Min(a, b)
}