package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Register all API handlers
func registerAPIHandlers(mux *http.ServeMux, botManager *BotManager) {
	// API auth route
	mux.HandleFunc("/api/auth", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r)
		
		if r.Method == "OPTIONS" {
			return
		}
		
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var data struct {
			Token string `json:"token"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid data", http.StatusBadRequest)
			return
		}

		// Make sure token starts with "Bot "
		if !strings.HasPrefix(data.Token, "Bot ") {
			data.Token = "Bot " + data.Token
		}

		// Validate token and get bot user info
		valid, userInfo := validateToken(data.Token)
		if !valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Create new session with UUID
		sessionID := generateRandomName("session_", 32)
		
		// Encrypt token for storage
		encryptedToken, err := botManager.encryptToken(data.Token)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		botManager.mutex.Lock()
		botManager.Bots[encryptedToken] = &Bot{
			Token:        data.Token,
			LastActive:   time.Now(),
			SessionID:    sessionID,
			ActivityLogs: []LogEntry{},
			UserInfo:     userInfo,
		}
		botManager.Sessions[sessionID] = encryptedToken
		botManager.SessionTimes[sessionID] = time.Now()
		botManager.mutex.Unlock()

		// Add login log
		botManager.AddLogEntry(encryptedToken, "LOGIN", "SYSTEM", "Successfully logged in", true)

		resp := map[string]interface{}{
			"session_id": sessionID,
			"message":    "Successfully logged in",
			"bot_info":   userInfo,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// API guilds route
	mux.HandleFunc("/api/guilds", validateSession(botManager, func(w http.ResponseWriter, r *http.Request, encryptedToken string) {
		// Decrypt token
		token, err := botManager.decryptToken(encryptedToken)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		guilds, err := fetchGuilds(token, botManager.rateLimiter)
		if err != nil {
			http.Error(w, "Error fetching guilds: "+err.Error(), http.StatusInternalServerError)
			botManager.AddLogEntry(encryptedToken, "FETCH_GUILDS", "API", "Failed to fetch guilds: "+err.Error(), false)
			return
		}

		botManager.AddLogEntry(encryptedToken, "FETCH_GUILDS", "API", fmt.Sprintf("Successfully fetched %d guilds", len(guilds)), true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(guilds)
	}))

	// Add more handlers here...
}

// Session validation middleware
func validateSession(botManager *BotManager, handler func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r)
		
		if r.Method == "OPTIONS" {
			return
		}

		sessionID := r.Header.Get("X-Session-ID")
		if sessionID == "" {
			http.Error(w, "Session ID required", http.StatusUnauthorized)
			return
		}

		botManager.mutex.RLock()
		encryptedToken, exists := botManager.Sessions[sessionID]
		lastActive, timeExists := botManager.SessionTimes[sessionID]
		botManager.mutex.RUnlock()

		if !exists || !timeExists {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		// Check session timeout
		if time.Since(lastActive) > botManager.timeout {
			botManager.mutex.Lock()
			delete(botManager.Sessions, sessionID)
			delete(botManager.SessionTimes, sessionID)
			botManager.mutex.Unlock()
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		// Update last active time
		botManager.mutex.Lock()
		botManager.SessionTimes[sessionID] = time.Now()
		botManager.mutex.Unlock()

		handler(w, r, encryptedToken)
	}
}