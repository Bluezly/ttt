package main

import (
	"time"
)

// Bot structure with enhanced fields
type Bot struct {
	Token        string      `json:"token"`
	LastActive   time.Time   `json:"last_active"`
	SessionID    string      `json:"session_id"`
	Permissions  []string    `json:"permissions"`
	ActivityLogs []LogEntry  `json:"activity_logs"`
	UserInfo     User        `json:"user_info"`
}

// LogEntry represents a single activity log
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Details   string    `json:"details"`
	Success   bool      `json:"success"`
}

// Guild represents a Discord server
type Guild struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Icon          string `json:"icon"`
	OwnerId       string `json:"owner_id"`
	OwnerUsername string `json:"owner_username,omitempty"`
	MemberCount   int    `json:"member_count"`
	InviteURL     string `json:"invite_url,omitempty"`
	IconURL       string `json:"icon_url,omitempty"`
}

// Channel represents a Discord channel
type Channel struct {
	ID       string `json:"id"`
	Type     int    `json:"type"`
	GuildID  string `json:"guild_id"`
	Name     string `json:"name"`
	Position int    `json:"position"`
}

// Role represents a Discord role
type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Color       int    `json:"color"`
	Position    int    `json:"position"`
	Permissions string `json:"permissions"`
}

// Member represents a guild member
type Member struct {
	User     User     `json:"user"`
	Nick     string   `json:"nick"`
	Roles    []string `json:"roles"`
	JoinedAt string   `json:"joined_at"`
}

// User represents a Discord user
type User struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Avatar        string `json:"avatar"`
	Bot           bool   `json:"bot"`
	AvatarURL     string `json:"avatar_url,omitempty"`
}

// Invite represents a Discord invite
type Invite struct {
	Code      string `json:"code"`
	GuildID   string `json:"guild_id"`
	ChannelID string `json:"channel_id"`
}

// GuildDetails represents detailed information about a guild
type GuildDetails struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	MemberCount int    `json:"approximate_member_count"`
}