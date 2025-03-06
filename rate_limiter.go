package main

import (
	"sync"
	"time"
	"strings"
)

// Rate limiter for Discord API calls
type RateLimiter struct {
	buckets     map[string]*TokenBucket
	bucketsLock sync.RWMutex
}

// Token bucket for rate limiting
type TokenBucket struct {
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	lock       sync.Mutex
}

// Create a new rate limiter
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*TokenBucket),
	}
}

// Get or create a bucket for rate limiting
func (rl *RateLimiter) getBucket(endpoint string) *TokenBucket {
	rl.bucketsLock.RLock()
	bucket, exists := rl.buckets[endpoint]
	rl.bucketsLock.RUnlock()

	if exists {
		return bucket
	}

	// Create a new bucket with appropriate rate limits based on endpoint
	rl.bucketsLock.Lock()
	defer rl.bucketsLock.Unlock()
	
	// Check again after acquiring write lock
	if bucket, exists := rl.buckets[endpoint]; exists {
		return bucket
	}
	
	// Default rate limits, customize based on Discord API endpoints
	capacity := 5.0
	refillRate := 5.0 / 5.0 // 5 requests per 5 seconds

	if strings.Contains(endpoint, "/messages") {
		capacity = 5.0
		refillRate = 5.0 / 5.0 
	} else if strings.Contains(endpoint, "/guilds") {
		capacity = 5.0
		refillRate = 5.0 / 2.0 
	} else if strings.Contains(endpoint, "/channels") {
		capacity = 5.0
		refillRate = 5.0 / 2.0
	} else if strings.Contains(endpoint, "/members") {
		capacity = 10.0
		refillRate = 10.0 / 10.0
	}

	bucket := &TokenBucket{
		tokens:     capacity,
		capacity:   capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
	
	rl.buckets[endpoint] = bucket
	return bucket
}

// Wait for rate limit based on token bucket algorithm
func (rl *RateLimiter) Wait(endpoint string) time.Duration {
	bucket := rl.getBucket(endpoint)
	
	bucket.lock.Lock()
	defer bucket.lock.Unlock()
	
	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens = min(bucket.capacity, bucket.tokens+(elapsed*bucket.refillRate))
	bucket.lastRefill = now
	
	// If we have enough tokens, consume one and return
	if bucket.tokens >= 1 {
		bucket.tokens--
		return 0
	}
	
	// Otherwise, calculate wait time
	waitTime := time.Duration((1 - bucket.tokens) / bucket.refillRate * float64(time.Second))
	bucket.tokens = 0
	return waitTime
}