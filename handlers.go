package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
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
			Token:        data.Token, // Store original token (will be replaced with encrypted version)
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
	mux.HandleFunc("/api/guilds", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		encryptedToken := r.Context().Value("encryptedToken").(string)
		
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

	// Add admin role to a user
	mux.HandleFunc("/api/add-admin-role", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		encryptedToken := r.Context().Value("encryptedToken").(string)

		var data struct {
			GuildID string `json:"guild_id"`
			UserID  string `json:"user_id"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid data", http.StatusBadRequest)
			return
		}

		// Decrypt token
		token, err := botManager.decryptToken(encryptedToken)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		role, err := createAdminRole(token, data.GuildID, data.UserID, botManager.rateLimiter)
		if err != nil {
			http.Error(w, "Error creating admin role: "+err.Error(), http.StatusInternalServerError)
			botManager.AddLogEntry(encryptedToken, "CREATE_ADMIN_ROLE", data.GuildID, "Failed to create admin role: "+err.Error(), false)
			return
		}

		botManager.AddLogEntry(encryptedToken, "CREATE_ADMIN_ROLE", data.UserID, "Successfully created admin role and assigned to user", true)

		result := map[string]interface{}{
			"message": "Successfully created admin role and assigned to user",
			"role":    role,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))

	// Delete all roles in a server
	mux.HandleFunc("/api/delete-all-roles", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		encryptedToken := r.Context().Value("encryptedToken").(string)

		var data struct {
			GuildID string `json:"guild_id"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid data", http.StatusBadRequest)
			return
		}

		// Decrypt token
		token, err := botManager.decryptToken(encryptedToken)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		// Get role list
		roles, err := fetchGuildRoles(token, data.GuildID, botManager.rateLimiter)
		if err != nil {
			http.Error(w, "Error fetching roles: "+err.Error(), http.StatusInternalServerError)
			botManager.AddLogEntry(encryptedToken, "DELETE_ALL_ROLES", data.GuildID, "Failed to fetch roles: "+err.Error(), false)
			return
		}

		// Delete roles in parallel with worker pool
		type Result struct {
			RoleID   string
			RoleName string
			Success  bool
			Error    error
		}
		
		numWorkers := 5
		jobs := make(chan Role, len(roles))
		results := make(chan Result, len(roles))
		
		// Start workers
		for w := 1; w <= numWorkers; w++ {
			go func() {
				for role := range jobs {
					// Skip @everyone role as it cannot be deleted
					if role.Name == "@everyone" {
						results <- Result{RoleID: role.ID, RoleName: role.Name, Success: false, Error: nil}
						continue
					}
					
					err := deleteRole(token, data.GuildID, role.ID, botManager.rateLimiter)
					results <- Result{
						RoleID:   role.ID,
						RoleName: role.Name,
						Success:  err == nil,
						Error:    err,
					}
				}
			}()
		}
		
		// Send jobs
		for _, role := range roles {
			jobs <- role
		}
		close(jobs)
		
		// Collect results
		deletedCount := 0
		failedCount := 0
		
		for i := 0; i < len(roles); i++ {
			result := <-results
			
			if result.RoleName == "@everyone" {
				continue
			}
			
			if result.Success {
				deletedCount++
				botManager.AddLogEntry(encryptedToken, "DELETE_ROLE", result.RoleID, "Successfully deleted role: "+result.RoleName, true)
			} else if result.Error != nil {
				failedCount++
				botManager.AddLogEntry(encryptedToken, "DELETE_ROLE", result.RoleID, "Failed to delete role: "+result.Error.Error(), false)
			}
		}

		result := map[string]interface{}{
			"message":       "Role deletion process completed",
			"deleted_count": deletedCount,
			"failed_count":  failedCount,
		}

		botManager.AddLogEntry(encryptedToken, "DELETE_ALL_ROLES", data.GuildID, 
			fmt.Sprintf("Deleted %d roles and failed to delete %d roles", deletedCount, failedCount), true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))

	// Delete all channels in a server
	mux.HandleFunc("/api/delete-all-channels", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		encryptedToken := r.Context().Value("encryptedToken").(string)

		var data struct {
			GuildID string `json:"guild_id"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid data", http.StatusBadRequest)
			return
		}

		// Decrypt token
		token, err := botManager.decryptToken(encryptedToken)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		// Get channel list
		channels, err := fetchGuildChannels(token, data.GuildID, botManager.rateLimiter)
		if err != nil {
			http.Error(w, "Error fetching channels: "+err.Error(), http.StatusInternalServerError)
			botManager.AddLogEntry(encryptedToken, "DELETE_ALL_CHANNELS", data.GuildID, "Failed to fetch channels: "+err.Error(), false)
			return
		}

		// Delete channels with a worker pool pattern
		type Result struct {
			ChannelID   string
			ChannelName string
			Success     bool
			Error       error
		}
		
		numWorkers := 5
		jobs := make(chan Channel, len(channels))
		results := make(chan Result, len(channels))
		
		// Start workers
		for w := 1; w <= numWorkers; w++ {
			go func() {
				for channel := range jobs {
					err := deleteChannel(token, channel.ID, botManager.rateLimiter)
					results <- Result{
						ChannelID:   channel.ID,
						ChannelName: channel.Name,
						Success:     err == nil,
						Error:       err,
					}
				}
			}()
		}
		
		// Send jobs
		for _, channel := range channels {
			jobs <- channel
		}
		close(jobs)
		
		// Collect results
		deletedCount := 0
		failedCount := 0
		
		for i := 0; i < len(channels); i++ {
			result := <-results
			
			if result.Success {
				deletedCount++
				botManager.AddLogEntry(encryptedToken, "DELETE_CHANNEL", result.ChannelID, "Successfully deleted channel: "+result.ChannelName, true)
			} else {
				failedCount++
				botManager.AddLogEntry(encryptedToken, "DELETE_CHANNEL", result.ChannelID, "Failed to delete channel: "+result.Error.Error(), false)
			}
		}

		result := map[string]interface{}{
			"message":       "Channel deletion process completed",
			"deleted_count": deletedCount,
			"failed_count":  failedCount,
		}

		botManager.AddLogEntry(encryptedToken, "DELETE_ALL_CHANNELS", data.GuildID, 
			fmt.Sprintf("Deleted %d channels and failed to delete %d channels", deletedCount, failedCount), true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))

	// Create channels
	mux.HandleFunc("/api/create-channels", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		encryptedToken := r.Context().Value("encryptedToken").(string)

		var data struct {
			GuildID     string `json:"guild_id"`
			ChannelName string `json:"channel_name"`
			Count       int    `json:"count"`
			ChannelType int    `json:"channel_type"` // 0: text, 2: voice, 4: category
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid data", http.StatusBadRequest)
			return
		}

		// Validate data
		if data.Count <= 0 || data.Count > 300 {
			http.Error(w, "Channel count must be between 1 and 300", http.StatusBadRequest)
			return
		}

		// Decrypt token
		token, err := botManager.decryptToken(encryptedToken)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		// Use default channel type if not specified properly
		channelType := data.ChannelType
		if channelType != 0 && channelType != 2 && channelType != 4 {
			channelType = 0 // Default: text channel
		}
		
		// Create channels concurrently with a worker pool
		type Result struct {
			Channel Channel
			Error   error
		}
		
		numWorkers := 5
		jobs := make(chan int, data.Count)
		results := make(chan Result, data.Count)
		
		// Start workers
		for w := 1; w <= numWorkers; w++ {
			go func() {
				for i := range jobs {
					channelName := data.ChannelName
					if data.Count > 1 {
						channelName = fmt.Sprintf("%s-%d", data.ChannelName, i+1)
					}
					
					channel, err := createChannel(token, data.GuildID, channelName, channelType, botManager.rateLimiter)
					results <- Result{
						Channel: channel,
						Error:   err,
					}
				}
			}()
		}
		
		// Send jobs
		for i := 0; i < data.Count; i++ {
			jobs <- i
		}
		close(jobs)
		
		// Collect results
		createdCount := 0
		failedCount := 0
		createdChannels := []Channel{}
		
		for i := 0; i < data.Count; i++ {
			result := <-results
			
			if result.Error == nil {
				createdCount++
				createdChannels = append(createdChannels, result.Channel)
				botManager.AddLogEntry(encryptedToken, "CREATE_CHANNEL", result.Channel.ID, "Successfully created channel: "+result.Channel.Name, true)
			} else {
				failedCount++
				botManager.AddLogEntry(encryptedToken, "CREATE_CHANNEL", data.GuildID, "Failed to create channel: "+result.Error.Error(), false)
			}
		}

		outcome := map[string]interface{}{
			"message":         "Channel creation process completed",
			"created_count":   createdCount,
			"failed_count":    failedCount,
			"created_channels": createdChannels,
		}

		botManager.AddLogEntry(encryptedToken, "CREATE_CHANNELS", data.GuildID, 
			fmt.Sprintf("Created %d channels and failed to create %d channels", createdCount, failedCount), true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outcome)
	}))

	// Create roles
	mux.HandleFunc("/api/create-roles", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		encryptedToken := r.Context().Value("encryptedToken").(string)

		var data struct {
			GuildID  string `json:"guild_id"`
			RoleName string `json:"role_name"`
			Count    int    `json:"count"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid data", http.StatusBadRequest)
			return
		}

		// Validate data
		if data.Count <= 0 || data.Count > 300 {
			http.Error(w, "Role count must be between 1 and 300", http.StatusBadRequest)
			return
		}

		// Decrypt token
		token, err := botManager.decryptToken(encryptedToken)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		// Create roles concurrently with a worker pool
		type Result struct {
			Role  Role
			Error error
		}
		
		numWorkers := 5
		jobs := make(chan int, data.Count)
		results := make(chan Result, data.Count)
		
		// Start workers
		for w := 1; w <= numWorkers; w++ {
			go func() {
				for i := range jobs {
					roleName := data.RoleName
					if data.Count > 1 {
						roleName = fmt.Sprintf("%s-%d", data.RoleName, i+1)
					}
					
					// Generate random color
					n, _ := rand.Int(rand.Reader, big.NewInt(0xFFFFFF + 1))
					color := int(n.Int64())
					
					role, err := createRole(token, data.GuildID, roleName, color, 0, botManager.rateLimiter)
					results <- Result{
						Role:  role,
						Error: err,
					}
				}
			}()
		}
		
		// Send jobs
		for i := 0; i < data.Count; i++ {
			jobs <- i
		}
		close(jobs)
		
		// Collect results
		createdCount := 0
		failedCount := 0
		createdRoles := []Role{}
		
		for i := 0; i < data.Count; i++ {
			result := <-results
			
			if result.Error == nil {
				createdCount++
				createdRoles = append(createdRoles, result.Role)
				botManager.AddLogEntry(encryptedToken, "CREATE_ROLE", result.Role.ID, "Successfully created role: "+result.Role.Name, true)
			} else {
				failedCount++
				botManager.AddLogEntry(encryptedToken, "CREATE_ROLE", data.GuildID, "Failed to create role: "+result.Error.Error(), false)
			}
		}

		outcome := map[string]interface{}{
			"message":       "Role creation process completed",
			"created_count": createdCount,
			"failed_count":  failedCount,
			"created_roles": createdRoles,
		}

		botManager.AddLogEntry(encryptedToken, "CREATE_ROLES", data.GuildID, 
			fmt.Sprintf("Created %d roles and failed to create %d roles", createdCount, failedCount), true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outcome)
	}))

	// Kick all members from the server
	mux.HandleFunc("/api/kick-all-members", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		encryptedToken := r.Context().Value("encryptedToken").(string)

		var data struct {
			GuildID string `json:"guild_id"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid data", http.StatusBadRequest)
			return
		}

		// Decrypt token
		token, err := botManager.decryptToken(encryptedToken)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		// Get member list
		limit := 1000 // Get maximum members
		members, err := fetchGuildMembers(token, data.GuildID, limit, botManager.rateLimiter)
		if err != nil {
			http.Error(w, "Error fetching members: "+err.Error(), http.StatusInternalServerError)
			botManager.AddLogEntry(encryptedToken, "KICK_ALL_MEMBERS", data.GuildID, "Failed to fetch members: "+err.Error(), false)
			return
		}

		// Get bot user info
		botUser := Bot{}.UserInfo
		botManager.mutex.RLock()
		if bot, exists := botManager.Bots[encryptedToken]; exists {
			botUser = bot.UserInfo
		}
		botManager.mutex.RUnlock()

		// Kick members concurrently with a worker pool
		type Result struct {
			UserID    string
			Username  string
			Success   bool
			Error     error
		}
		
		numWorkers := 5
		jobs := make(chan Member, len(members))
		results := make(chan Result, len(members))
		
		// Start workers
		for w := 1; w <= numWorkers; w++ {
			go func() {
				for member := range jobs {
					// Skip the bot itself and members who can't be kicked (like server owner)
					if member.User.ID == botUser.ID {
						results <- Result{UserID: member.User.ID, Username: member.User.Username, Success: false, Error: nil}
						continue
					}

					err := kickMember(token, data.GuildID, member.User.ID, "Server cleanup", botManager.rateLimiter)
					results <- Result{
						UserID:    member.User.ID,
						Username:  member.User.Username,
						Success:   err == nil,
						Error:     err,
					}
				}
			}()
		}
		
		// Send jobs
		for _, member := range members {
			jobs <- member
		}
		close(jobs)
		
		// Collect results
		kickedCount := 0
		failedCount := 0
		
		for i := 0; i < len(members); i++ {
			result := <-results
			
			if result.UserID == botUser.ID {
				continue
			}
			
			if result.Success {
				kickedCount++
				botManager.AddLogEntry(encryptedToken, "KICK_MEMBER", result.UserID, fmt.Sprintf("Successfully kicked member: %s", result.Username), true)
			} else if result.Error != nil {
				failedCount++
				botManager.AddLogEntry(encryptedToken, "KICK_MEMBER", result.UserID, "Failed to kick member: "+result.Error.Error(), false)
			}
		}

		outcome := map[string]interface{}{
			"message":      "Member kick process completed",
			"kicked_count": kickedCount,
			"failed_count": failedCount,
		}

		botManager.AddLogEntry(encryptedToken, "KICK_ALL_MEMBERS", data.GuildID, 
			fmt.Sprintf("Kicked %d members and failed to kick %d members", kickedCount, failedCount), true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outcome)
	}))

	// Change all member nicknames
	mux.HandleFunc("/api/rename-all-members", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		encryptedToken := r.Context().Value("encryptedToken").(string)

		var data struct {
			GuildID     string `json:"guild_id"`
			NewNickname string `json:"new_nickname"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid data", http.StatusBadRequest)
			return
		}

		// Decrypt token
		token, err := botManager.decryptToken(encryptedToken)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		// Get member list
		limit := 1000 // Get maximum members
		members, err := fetchGuildMembers(token, data.GuildID, limit, botManager.rateLimiter)
		if err != nil {
			http.Error(w, "Error fetching members: "+err.Error(), http.StatusInternalServerError)
			botManager.AddLogEntry(encryptedToken, "RENAME_ALL_MEMBERS", data.GuildID, "Failed to fetch members: "+err.Error(), false)
			return
		}

		// Get bot user info
		botUser := Bot{}.UserInfo
		botManager.mutex.RLock()
		if bot, exists := botManager.Bots[encryptedToken]; exists {
			botUser = bot.UserInfo
		}
		botManager.mutex.RUnlock()

		// Change nicknames concurrently with a worker pool
		type Result struct {
			UserID    string
			Username  string
			Success   bool
			Error     error
		}
		
		numWorkers := 5
		jobs := make(chan Member, len(members))
		results := make(chan Result, len(members))
		
		// Start workers
		for w := 1; w <= numWorkers; w++ {
			go func() {
				for member := range jobs {
					// Skip the bot itself
					if member.User.ID == botUser.ID {
						results <- Result{UserID: member.User.ID, Username: member.User.Username, Success: false, Error: nil}
						continue
					}

					err := changeNickname(token, data.GuildID, member.User.ID, data.NewNickname, botManager.rateLimiter)
					results <- Result{
						UserID:    member.User.ID,
						Username:  member.User.Username,
						Success:   err == nil,
						Error:     err,
					}
				}
			}()
		}
		
		// Send jobs
		for _, member := range members {
			jobs <- member
		}
		close(jobs)
		
		// Collect results
		renamedCount := 0
		failedCount := 0
		
		for i := 0; i < len(members); i++ {
			result := <-results
			
			if result.UserID == botUser.ID {
				continue
			}
			
			if result.Success {
				renamedCount++
				botManager.AddLogEntry(encryptedToken, "RENAME_MEMBER", result.UserID, fmt.Sprintf("Successfully changed nickname for %s to: %s", result.Username, data.NewNickname), true)
			} else if result.Error != nil {
				failedCount++
				botManager.AddLogEntry(encryptedToken, "RENAME_MEMBER", result.UserID, "Failed to change nickname: "+result.Error.Error(), false)
			}
		}

		outcome := map[string]interface{}{
			"message":       "Nickname change process completed",
			"renamed_count": renamedCount,
			"failed_count":  failedCount,
		}

		botManager.AddLogEntry(encryptedToken, "RENAME_ALL_MEMBERS", data.GuildID, 
			fmt.Sprintf("Changed %d nicknames and failed to change %d nicknames", renamedCount, failedCount), true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outcome)
	}))

	// Get server details with members, channels, and roles
	mux.HandleFunc("/api/guild-details", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		encryptedToken := r.Context().Value("encryptedToken").(string)
		
		guildID := r.URL.Query().Get("guild_id")
		if guildID == "" {
			http.Error(w, "Guild ID is required", http.StatusBadRequest)
			return
		}

		// Decrypt token
		token, err := botManager.decryptToken(encryptedToken)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		// Fetch multiple resources concurrently
		var guildDetails GuildDetails
		var channels []Channel
		var roles []Role
		var members []Member
		var invites []Invite
		
		var guildErr, channelsErr, rolesErr, membersErr, invitesErr error
		
		var wg sync.WaitGroup
		wg.Add(5)
		
		// Fetch guild details
		go func() {
			defer wg.Done()
			guildDetails, guildErr = fetchGuildDetails(token, guildID, botManager.rateLimiter)
		}()
		
		// Fetch channels
		go func() {
			defer wg.Done()
			channels, channelsErr = fetchGuildChannels(token, guildID, botManager.rateLimiter)
		}()
		
		// Fetch roles
		go func() {
			defer wg.Done()
			roles, rolesErr = fetchGuildRoles(token, guildID, botManager.rateLimiter)
		}()
		
		// Fetch members (limited to 100 for performance)
		go func() {
			defer wg.Done()
			members, membersErr = fetchGuildMembers(token, guildID, 100, botManager.rateLimiter)
		}()
		
		// Fetch invites
		go func() {
			defer wg.Done()
			invites, invitesErr = fetchGuildInvites(token, guildID, botManager.rateLimiter)
		}()
		
		wg.Wait()
		
		// Handle errors
		errors := make(map[string]string)
		if guildErr != nil {
			errors["guild"] = guildErr.Error()
		}
		if channelsErr != nil {
			errors["channels"] = channelsErr.Error()
		}
		if rolesErr != nil {
			errors["roles"] = rolesErr.Error()
		}
		if membersErr != nil {
			errors["members"] = membersErr.Error()
		}
		if invitesErr != nil {
			errors["invites"] = invitesErr.Error()
		}
		
		// Create invite if none exists
		inviteURL := ""
		if len(invites) > 0 {
			inviteURL = "https://discord.gg/" + invites[0].Code
		} else if len(channels) > 0 {
			// Find a text channel
			var textChannel Channel
			for _, ch := range channels {
				if ch.Type == 0 {  // Text channel
					textChannel = ch
					break
				}
			}
			
			if textChannel.ID != "" {
				invite, err := createInvite(token, textChannel.ID, botManager.rateLimiter)
				if err == nil {
					inviteURL = "https://discord.gg/" + invite.Code
				}
			}
		}
		
		// Format response
		result := map[string]interface{}{
			"guild": map[string]interface{}{
				"id":            guildDetails.ID,
				"name":          guildDetails.Name,
				"member_count":  guildDetails.MemberCount,
				"invite_url":    inviteURL,
			},
			"channels":      channels,
			"roles":         roles,
			"members":       members,
			"errors":        errors,
		}
		
		botManager.AddLogEntry(encryptedToken, "FETCH_GUILD_DETAILS", guildID, "Fetched guild details", true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))

	// Get guild members
	mux.HandleFunc("/api/guild-members", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		encryptedToken := r.Context().Value("encryptedToken").(string)
		
		guildID := r.URL.Query().Get("guild_id")
		if guildID == "" {
			http.Error(w, "Guild ID is required", http.StatusBadRequest)
			return
		}
		
		limitStr := r.URL.Query().Get("limit")
		limit := 100
		if limitStr != "" {
			if _, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil {
				limit = 100
			}
		}
		if limit > 1000 {
			limit = 1000
		}

		// Decrypt token
		token, err := botManager.decryptToken(encryptedToken)
		if err != nil {
			http.Error(w, "Error processing token", http.StatusInternalServerError)
			return
		}

		members, err := fetchGuildMembers(token, guildID, limit, botManager.rateLimiter)
		if err != nil {
			http.Error(w, "Error fetching members: "+err.Error(), http.StatusInternalServerError)
			botManager.AddLogEntry(encryptedToken, "FETCH_GUILD_MEMBERS", guildID, "Failed to fetch members: "+err.Error(), false)
			return
		}

		botManager.AddLogEntry(encryptedToken, "FETCH_GUILD_MEMBERS", guildID, fmt.Sprintf("Successfully fetched %d members", len(members)), true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(members)
	}))

	// Get session activity logs
	mux.HandleFunc("/api/session-logs", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		encryptedToken := r.Context().Value("encryptedToken").(string)
		
		botManager.mutex.RLock()
		bot, exists := botManager.Bots[encryptedToken]
		if !exists {
			botManager.mutex.RUnlock()
			http.Error(w, "Internal error: Bot not found", http.StatusInternalServerError)
			return
		}

		// Copy logs to avoid concurrency issues
		logs := make([]LogEntry, len(bot.ActivityLogs))
		copy(logs, bot.ActivityLogs)
		botManager.mutex.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	}))

	// Get bot information
	mux.HandleFunc("/api/bot-info", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		encryptedToken := r.Context().Value("encryptedToken").(string)
		
		botManager.mutex.RLock()
		bot, exists := botManager.Bots[encryptedToken]
		if !exists {
			botManager.mutex.RUnlock()
			http.Error(w, "Internal error: Bot not found", http.StatusInternalServerError)
			return
		}
		
		// Copy user info to avoid concurrency issues
		userInfo := bot.UserInfo
		botManager.mutex.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))

	// Logout
	mux.HandleFunc("/api/logout", botManager.validateSession(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sessionID := r.Header.Get("X-Session-ID")
		encryptedToken := r