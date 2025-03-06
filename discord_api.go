package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Enhanced token validation with proxy and user agent rotation
func validateToken(token string) (bool, User) {
	if len(token) < 50 || !strings.HasPrefix(token, "Bot ") {
		return false, User{}
	}

	// Test token with Discord API
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", "https://discord.com/api/v10/users/@me", nil)
	if err != nil {
		return false, User{}
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("User-Agent", getRandomUserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return false, User{}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var user User
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, User{}
		}
		
		if err := json.Unmarshal(body, &user); err != nil {
			return false, User{}
		}
		
		// Add avatar URL if available
		if user.Avatar != "" {
			user.AvatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", user.ID, user.Avatar)
		}
		
		return true, user
	}
	
	return false, User{}
}

// Make Discord API request with rate limiting and retries
func makeDiscordRequest(token, method, endpoint string, body io.Reader, rateLimiter *RateLimiter) (*http.Response, error) {
	// Wait for rate limiter
	waitTime := rateLimiter.Wait(endpoint)
	if waitTime > 0 {
		time.Sleep(waitTime)
	}
	
	// Make request
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(method, fmt.Sprintf("https://discord.com/api/v10%s", endpoint), body)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", token)
	req.Header.Set("User-Agent", getRandomUserAgent())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	
	// Handle rate limiting
	if resp.StatusCode == 429 {
		defer resp.Body.Close()
		
		var rateLimitInfo struct {
			RetryAfter float64 `json:"retry_after"`
			Global     bool    `json:"global"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&rateLimitInfo); err != nil {
			// If we can't decode, use a default wait time
			time.Sleep(5 * time.Second)
		} else {
			// Add a little buffer
			waitTime := time.Duration(rateLimitInfo.RetryAfter*1000+100) * time.Millisecond
			time.Sleep(waitTime)
		}
		
		// Retry once
		return makeDiscordRequest(token, method, endpoint, body, rateLimiter)
	}
	
	return resp, nil
}

// Get bot's server list with enhanced info
func fetchGuilds(token string, rateLimiter *RateLimiter) ([]Guild, error) {
	resp, err := makeDiscordRequest(token, "GET", "/users/@me/guilds", nil, rateLimiter)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch guilds: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var guilds []Guild
	if err := json.Unmarshal(body, &guilds); err != nil {
		return nil, err
	}
	
	// Enhance guild data with member count and invite
	for i := range guilds {
		// Add icon URL if available
		if guilds[i].Icon != "" {
			guilds[i].IconURL = fmt.Sprintf("https://cdn.discordapp.com/icons/%s/%s.png", guilds[i].ID, guilds[i].Icon)
		}
		
		// Get guild details
		guildDetails, err := fetchGuildDetails(token, guilds[i].ID, rateLimiter)
		if err == nil {
			guilds[i].MemberCount = guildDetails.MemberCount
		}
		
		// Get guild invite
		invites, err := fetchGuildInvites(token, guilds[i].ID, rateLimiter)
		if err == nil && len(invites) > 0 {
			guilds[i].InviteURL = "https://discord.gg/" + invites[0].Code
		} else {
			// Try to create an invite if none exists
			channels, err := fetchGuildChannels(token, guilds[i].ID, rateLimiter)
			if err == nil && len(channels) > 0 {
				// Find a text channel
				var textChannel Channel
				for _, ch := range channels {
					if ch.Type == 0 {  // Text channel
						textChannel = ch
						break
					}
				}
				
				if textChannel.ID != "" {
					invite, err := createInvite(token, textChannel.ID, rateLimiter)
					if err == nil {
						guilds[i].InviteURL = "https://discord.gg/" + invite.Code
					}
				}
			}
		}
		
		// Get owner details
		if guilds[i].OwnerId != "" {
			owner, err := fetchUser(token, guilds[i].OwnerId, rateLimiter)
			if err == nil {
				guilds[i].OwnerUsername = owner.Username
			}
		}
		
		// Add a small delay to avoid rate limits
		time.Sleep(200 * time.Millisecond)
	}

	return guilds, nil
}

// Fetch guild details including member count
func fetchGuildDetails(token string, guildID string, rateLimiter *RateLimiter) (GuildDetails, error) {
	resp, err := makeDiscordRequest(token, "GET", fmt.Sprintf("/guilds/%s?with_counts=true", guildID), nil, rateLimiter)
	if err != nil {
		return GuildDetails{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return GuildDetails{}, fmt.Errorf("failed to fetch guild details: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return GuildDetails{}, err
	}

	var guildDetails GuildDetails
	if err := json.Unmarshal(body, &guildDetails); err != nil {
		return GuildDetails{}, err
	}

	return guildDetails, nil
}

// Fetch user details
func fetchUser(token string, userID string, rateLimiter *RateLimiter) (User, error) {
	resp, err := makeDiscordRequest(token, "GET", fmt.Sprintf("/users/%s", userID), nil, rateLimiter)
	if err != nil {
		return User{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return User{}, fmt.Errorf("failed to fetch user: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return User{}, err
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return User{}, err
	}
	
	// Add avatar URL if available
	if user.Avatar != "" {
		user.AvatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", user.ID, user.Avatar)
	}

	return user, nil
}

// Get or create invite
func fetchGuildInvites(token string, guildID string, rateLimiter *RateLimiter) ([]Invite, error) {
	resp, err := makeDiscordRequest(token, "GET", fmt.Sprintf("/guilds/%s/invites", guildID), nil, rateLimiter)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch invites: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var invites []Invite
	if err := json.Unmarshal(body, &invites); err != nil {
		return nil, err
	}

	return invites, nil
}

// Create an invite
func createInvite(token string, channelID string, rateLimiter *RateLimiter) (Invite, error) {
	payload := map[string]interface{}{
		"max_age": 0,
		"max_uses": 0,
		"temporary": false,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return Invite{}, err
	}
	
	resp, err := makeDiscordRequest(token, "POST", fmt.Sprintf("/channels/%s/invites", channelID), strings.NewReader(string(jsonData)), rateLimiter)
	if err != nil {
		return Invite{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return Invite{}, fmt.Errorf("failed to create invite: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Invite{}, err
	}

	var invite Invite
	if err := json.Unmarshal(body, &invite); err != nil {
		return Invite{}, err
	}

	return invite, nil
}

// Get members in a server with enhanced efficiency
func fetchGuildMembers(token string, guildID string, limit int, rateLimiter *RateLimiter) ([]Member, error) {
	allMembers := []Member{}
	after := "0"
	batchSize := 1000 // Max batch size allowed by Discord
	
	// Adjust limit if needed
	if limit <= 0 {
		limit = batchSize
	}
	
	for len(allMembers) < limit {
		endpoint := fmt.Sprintf("/guilds/%s/members?limit=%d&after=%s", guildID, min(float64(batchSize), float64(limit-len(allMembers))), after)
		resp, err := makeDiscordRequest(token, "GET", endpoint, nil, rateLimiter)
		if err != nil {
			return allMembers, err
		}
		
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		
		if resp.StatusCode != 200 {
			return allMembers, fmt.Errorf("failed to fetch members: %d", resp.StatusCode)
		}
		
		var members []Member
		if err := json.Unmarshal(body, &members); err != nil {
			return allMembers, err
		}
		
		// No more members
		if len(members) == 0 {
			break
		}
		
		allMembers = append(allMembers, members...)
		
		// Update after for next request
		after = members[len(members)-1].User.ID
		
		// If we got fewer members than requested, we're at the end
		if len(members) < batchSize {
			break
		}
		
		// Respect rate limits
		time.Sleep(300 * time.Millisecond)
	}
	
	return allMembers, nil
}

// Get channels in a server
func fetchGuildChannels(token string, guildID string, rateLimiter *RateLimiter) ([]Channel, error) {
	resp, err := makeDiscordRequest(token, "GET", fmt.Sprintf("/guilds/%s/channels", guildID), nil, rateLimiter)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch channels: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var channels []Channel
	if err := json.Unmarshal(body, &channels); err != nil {
		return nil, err
	}

	return channels, nil
}

// Get roles in a server
func fetchGuildRoles(token string, guildID string, rateLimiter *RateLimiter) ([]Role, error) {
	resp, err := makeDiscordRequest(token, "GET", fmt.Sprintf("/guilds/%s/roles", guildID), nil, rateLimiter)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch roles: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var roles []Role
	if err := json.Unmarshal(body, &roles); err != nil {
		return nil, err
	}

	return roles, nil
}

// Kick a member from the server
func kickMember(token string, guildID string, userID string, reason string, rateLimiter *RateLimiter) error {
	endpoint := fmt.Sprintf("/guilds/%s/members/%s", guildID, userID)
	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://discord.com/api/v10%s", endpoint), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("User-Agent", getRandomUserAgent())
	if reason != "" {
		req.Header.Set("X-Audit-Log-Reason", reason)
	}
	
	// Wait for rate limiter
	waitTime := rateLimiter.Wait(endpoint)
	if waitTime > 0 {
		time.Sleep(waitTime)
	}
	
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to kick member: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// Change member nickname
func changeNickname(token string, guildID string, userID string, newNick string, rateLimiter *RateLimiter) error {
	payload := map[string]string{"nick": newNick}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	
	endpoint := fmt.Sprintf("/guilds/%s/members/%s", guildID, userID)
	resp, err := makeDiscordRequest(token, "PATCH", endpoint, strings.NewReader(string(jsonData)), rateLimiter)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to change nickname: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// Delete a channel
func deleteChannel(token string, channelID string, rateLimiter *RateLimiter) error {
	endpoint := fmt.Sprintf("/channels/%s", channelID)
	resp, err := makeDiscordRequest(token, "DELETE", endpoint, nil, rateLimiter)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete channel: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// Create a new channel
func createChannel(token string, guildID string, name string, channelType int, rateLimiter *RateLimiter) (Channel, error) {
	payload := map[string]interface{}{
		"name": name,
		"type": channelType,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return Channel{}, err
	}
	
	endpoint := fmt.Sprintf("/guilds/%s/channels", guildID)
	resp, err := makeDiscordRequest(token, "POST", endpoint, strings.NewReader(string(jsonData)), rateLimiter)
	if err != nil {
		return Channel{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		return Channel{}, fmt.Errorf("failed to create channel: %d - %s", resp.StatusCode, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Channel{}, err
	}

	var channel Channel
	if err := json.Unmarshal(body, &channel); err != nil {
		return Channel{}, err
	}

	return channel, nil
}

// Create a new role
func createRole(token string, guildID string, name string, color int, permissions int64, rateLimiter *RateLimiter) (Role, error) {
	payload := map[string]interface{}{
		"name": name,
		"color": color,
		"permissions": permissions,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return Role{}, err
	}
	
	endpoint := fmt.Sprintf("/guilds/%s/roles", guildID)
	resp, err := makeDiscordRequest(token, "POST", endpoint, strings.NewReader(string(jsonData)), rateLimiter)
	if err != nil {
		return Role{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return Role{}, fmt.Errorf("failed to create role: %d - %s", resp.StatusCode, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Role{}, err
	}

	var role Role
	if err := json.Unmarshal(body, &role); err != nil {
		return Role{}, err
	}

	return role, nil
}

// Delete a role
func deleteRole(token string, guildID string, roleID string, rateLimiter *RateLimiter) error {
	endpoint := fmt.Sprintf("/guilds/%s/roles/%s", guildID, roleID)
	resp, err := makeDiscordRequest(token, "DELETE", endpoint, nil, rateLimiter)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete role: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// Add role to a member
func addRoleToMember(token string, guildID string, userID string, roleID string, rateLimiter *RateLimiter) error {
	endpoint := fmt.Sprintf("/guilds/%s/members/%s/roles/%s", guildID, userID, roleID)
	resp, err := makeDiscordRequest(token, "PUT", endpoint, nil, rateLimiter)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to assign role: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// Create an admin role with all permissions
func createAdminRole(token string, guildID string, userId string, rateLimiter *RateLimiter) (Role, error) {
	// Create a role with administrator permissions (8 = administrator permission)
	adminRole, err := createRole(token, guildID, "ServerAdmin", 0xFF0000, 8, rateLimiter)
	if err != nil {
		return Role{}, err
	}
	
	// Assign the role to the user
	err = addRoleToMember(token, guildID, userId, adminRole.ID, rateLimiter)
	if err != nil {
		// Try to delete the role if assignment fails
		deleteRole(token, guildID, adminRole.ID, rateLimiter)
		return Role{}, err
	}
	
	return adminRole, nil
}