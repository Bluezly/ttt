package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

// Bot manager and session controller
type BotManager struct {
	Bots         map[string]*Bot
	Sessions     map[string]string // SessionID -> Token
	SessionTimes map[string]time.Time
	mutex        sync.RWMutex
	timeout      time.Duration
	rateLimiter  *RateLimiter
	encryptionKey []byte
}

// Create a new bot manager with enhanced security and performance
func NewBotManager() *BotManager {
	// Generate a random encryption key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatal("Failed to generate encryption key:", err)
	}
	
	manager := &BotManager{
		Bots:         make(map[string]*Bot),
		Sessions:     make(map[string]string),
		SessionTimes: make(map[string]time.Time),
		timeout:      30 * time.Minute, // Extended session timeout
		rateLimiter:  NewRateLimiter(),
		encryptionKey: key,
	}

	// Start the session cleanup process
	go manager.cleanupSessions()

	return manager
}

// Periodically clean up expired sessions
func (bm *BotManager) cleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C
		bm.mutex.Lock()

		now := time.Now()
		for sessionID, lastActive := range bm.SessionTimes {
			if now.Sub(lastActive) > bm.timeout {
				encryptedToken, exists := bm.Sessions[sessionID]
				if exists {
					bm.AddLogEntry(encryptedToken, "SESSION_TIMEOUT", "SYSTEM", "Session terminated due to timeout", true)
					delete(bm.Sessions, sessionID)
					delete(bm.SessionTimes, sessionID)
					log.Printf("Session %s terminated due to timeout", sessionID)
				}
			}
		}

		bm.mutex.Unlock()
	}
}

// Add activity log for the bot
func (bm *BotManager) AddLogEntry(encryptedToken string, action, target, details string, success bool) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	bot, exists := bm.Bots[encryptedToken]
	if !exists {
		return
	}

	logEntry := LogEntry{
		Timestamp: time.Now(),
		Action:    action,
		Target:    target,
		Details:   details,
		Success:   success,
	}

	// Keep log size manageable
	if len(bot.ActivityLogs) >= 500 {
		bot.ActivityLogs = bot.ActivityLogs[len(bot.ActivityLogs)-499:]
	}
	bot.ActivityLogs = append(bot.ActivityLogs, logEntry)
}

// Enhanced token encryption with AES-GCM
func (bm *BotManager) encryptToken(token string) (string, error) {
	// Hash token with SHA-256
	hash := sha256.New()
	hash.Write([]byte(token))
	tokenHash := fmt.Sprintf("%x", hash.Sum(nil))
	
	// Create a new AES cipher using our key
	block, err := aes.NewCipher(bm.encryptionKey)
	if err != nil {
		return "", err
	}
	
	// Create a nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	
	// Create GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	// Encrypt
	ciphertext := aesgcm.Seal(nil, nonce, []byte(token), nil)
	
	// Combine nonce and ciphertext and encode
	encrypted := base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))
	
	// Store the encrypted token
	bm.Bots[tokenHash] = &Bot{
		Token: encrypted,
		LastActive: time.Now(),
	}
	
	return tokenHash, nil
}

// Decrypt token
func (bm *BotManager) decryptToken(encryptedToken string) (string, error) {
	bm.mutex.RLock()
	bot, exists := bm.Bots[encryptedToken]
	bm.mutex.RUnlock()
	
	if !exists {
		return "", fmt.Errorf("token not found")
	}
	
	// The real token is stored in the bot struct
	decodedStr, err := base64.StdEncoding.DecodeString(bot.Token)
	if err != nil {
		return "", err
	}
	
	if len(decodedStr) < 13 { // nonce (12) + at least 1 byte of ciphertext
		return "", fmt.Errorf("invalid token format")
	}
	
	// Extract nonce and ciphertext
	nonce := decodedStr[:12]
	ciphertext := decodedStr[12:]
	
	// Create a new AES cipher
	block, err := aes.NewCipher(bm.encryptionKey)
	if err != nil {
		return "", err
	}
	
	// Create GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	// Decrypt
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	
	return string(plaintext), nil
}