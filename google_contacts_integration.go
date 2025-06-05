package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// normalizePhoneNumber attempts to clean and normalize a phone number string.
// It removes non-numeric characters (except initial '+'), and for 10-digit numbers,
// assumes it's an Indian number and prefixes "91".
// Returns the normalized number (digits only) or an error.
func normalizePhoneNumber(phone string) (string, error) {
	// Keep initial '+' but remove other non-numeric characters
	var cleaned strings.Builder
	hasPlus := strings.HasPrefix(phone, "+")
	if hasPlus {
		phone = phone[1:] // Temporarily remove plus for cleaning
	}

	for _, r := range phone {
		if r >= '0' && r <= '9' {
			cleaned.WriteRune(r)
		}
	}
	normalized := cleaned.String()

	if normalized == "" {
		return "", errors.New("phone number is empty after cleaning")
	}

	// If original had '+', it's likely an international number, keep as is (digits only)
	// Otherwise, apply length-based rules (e.g., for Indian numbers)
	if !hasPlus {
		if len(normalized) == 10 {
			// Assume 10-digit numbers without '+' are Indian, prefix with 91
			// This is a common convention but might need adjustment for other regions/rules
			return "91" + normalized, nil
		}
		// Add more rules here if needed, e.g., for other country-specific lengths without '+'
	}

	// Basic validation: check if it's all digits now and has a reasonable length
	// This is a very basic check. Real-world validation is much more complex.
	if len(normalized) < 7 || len(normalized) > 15 { // Arbitrary min/max lengths
		return "", fmt.Errorf("phone number '%s' has invalid length after normalization", normalized)
	}

	return normalized, nil
}

var fetchContactsFromGoogleGroupFunc = func(authToken string, groupName string, forUserLog string) ([]map[string]string, error) {
	log.Info().Str("user_id", forUserLog).Str("groupName", groupName).Msg("Starting to fetch contacts from Google Group (REAL IMPLEMENTATION)")

	httpClient := http.DefaultClient

	var targetGroupResourceName string
	var pageToken string
	processedGroups := 0

	log.Debug().Str("user_id", forUserLog).Msg("Fetching contact groups from Google People API")
	for {
		groupsURL := "https://people.googleapis.com/v1/contactGroups?pageSize=100"
		if pageToken != "" {
			groupsURL += "&pageToken=" + pageToken
		}

		req, err := http.NewRequest("GET", groupsURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request for contact groups: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+authToken)
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			log.Error().Err(err).Str("user_id", forUserLog).Str("url", groupsURL).Msg("Failed HTTP request to fetch contact groups")
			return nil, fmt.Errorf("failed to execute request for contact groups: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				log.Error().Err(readErr).Str("user_id", forUserLog).Int("status_code", resp.StatusCode).Msg("Failed to read error response body from Google (contact groups)")
				return nil, fmt.Errorf("error fetching contact groups, status: %s, failed to read error body", resp.Status)
			}
			var googleErr GoogleApiError
			if json.Unmarshal(bodyBytes, &googleErr) == nil && googleErr.Error.Message != "" {
				log.Error().Str("user_id", forUserLog).Int("status_code", resp.StatusCode).Str("google_error_status", googleErr.Error.Status).Str("google_error_message", googleErr.Error.Message).Msg("Google API error fetching contact groups")
				return nil, fmt.Errorf("google API error fetching contact groups: %s (Status: %s)", googleErr.Error.Message, googleErr.Error.Status)
			}
			log.Error().Str("user_id", forUserLog).Int("status_code", resp.StatusCode).Str("response_body", string(bodyBytes)).Msg("Non-OK HTTP status fetching contact groups from Google")
			return nil, fmt.Errorf("error fetching contact groups, status: %s, body: %s", resp.Status, string(bodyBytes))
		}

		var groupListResp GoogleContactGroupListResponse
		if err := json.NewDecoder(resp.Body).Decode(&groupListResp); err != nil {
			return nil, fmt.Errorf("failed to decode contact groups response: %w", err)
		}

		for _, group := range groupListResp.ContactGroups {
			processedGroups++
			if strings.EqualFold(group.Name, groupName) || strings.EqualFold(group.FormattedName, groupName) {
				targetGroupResourceName = group.ResourceName
				log.Info().Str("user_id", forUserLog).Str("groupName", groupName).Str("resourceName", targetGroupResourceName).Msg("Found target contact group")
				break
			}
		}

		if targetGroupResourceName != "" {
			break
		}
		pageToken = groupListResp.NextPageToken
		if pageToken == "" {
			break
		}
	}
	log.Debug().Str("user_id", forUserLog).Int("total_groups_checked", processedGroups).Msg("Finished checking contact groups")


	if targetGroupResourceName == "" {
		return nil, fmt.Errorf("contact group '%s' not found for user %s", groupName, forUserLog)
	}

	var contactsResult []map[string]string
	pageToken = ""
	processedConnections := 0

	log.Debug().Str("user_id", forUserLog).Str("groupResourceName", targetGroupResourceName).Msg("Fetching connections for the target group from Google People API")
	for {
		connectionsURL := "https://people.googleapis.com/v1/people/me/connections?personFields=names,phoneNumbers,memberships&pageSize=100"
		if pageToken != "" {
			connectionsURL += "&pageToken=" + pageToken
		}

		req, err := http.NewRequest("GET", connectionsURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request for connections: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+authToken)
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			log.Error().Err(err).Str("user_id", forUserLog).Str("url", connectionsURL).Msg("Failed HTTP request to fetch connections")
			return nil, fmt.Errorf("failed to execute request for connections: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				log.Error().Err(readErr).Str("user_id", forUserLog).Int("status_code", resp.StatusCode).Msg("Failed to read error response body from Google (connections)")
				return nil, fmt.Errorf("error fetching connections, status: %s, failed to read error body", resp.Status)
			}
			var googleErr GoogleApiError
			if json.Unmarshal(bodyBytes, &googleErr) == nil && googleErr.Error.Message != "" {
				log.Error().Str("user_id", forUserLog).Int("status_code", resp.StatusCode).Str("google_error_status", googleErr.Error.Status).Str("google_error_message", googleErr.Error.Message).Msg("Google API error fetching connections")
				return nil, fmt.Errorf("google API error fetching connections: %s (Status: %s)", googleErr.Error.Message, googleErr.Error.Status)
			}
			log.Error().Str("user_id", forUserLog).Int("status_code", resp.StatusCode).Str("response_body", string(bodyBytes)).Msg("Non-OK HTTP status fetching connections from Google")
			return nil, fmt.Errorf("error fetching connections, status: %s, body: %s", resp.Status, string(bodyBytes))
		}

		var connListResp GoogleConnectionsListResponse
		if err := json.NewDecoder(resp.Body).Decode(&connListResp); err != nil {
			return nil, fmt.Errorf("failed to decode connections response: %w", err)
		}

		log.Debug().Str("user_id", forUserLog).Int("connections_in_page", len(connListResp.Connections)).Msg("Processing connections page")

		for _, person := range connListResp.Connections {
			processedConnections++
			isMember := false
			for _, membership := range person.Memberships {
				if membership.ContactGroupMembership.ContactGroupResourceName == targetGroupResourceName {
					isMember = true
					break
				}
			}

			if isMember {
				var displayName string
				if len(person.Names) > 0 {
					displayName = person.Names[0].DisplayName
				}

				var phoneNumber string
				if len(person.PhoneNumbers) > 0 {
					if person.PhoneNumbers[0].CanonicalForm != "" {
						phoneNumber = person.PhoneNumbers[0].CanonicalForm
					} else {
						phoneNumber = person.PhoneNumbers[0].Value
					}
				}

				if strings.TrimSpace(phoneNumber) != "" {
					contactsResult = append(contactsResult, map[string]string{"name": displayName, "phoneNumber": phoneNumber})
					log.Debug().Str("user_id", forUserLog).Str("contactName", displayName).Str("phoneNumber", phoneNumber).Msg("Added contact from group")
				} else {
					log.Warn().Str("user_id", forUserLog).Str("contactName", displayName).Msg("Contact in group has no phone number, skipping.")
				}
			}
		}

		pageToken = connListResp.NextPageToken
		if pageToken == "" {
			break
		}
	}
	log.Info().Str("user_id", forUserLog).Int("total_connections_checked", processedConnections).Int("contacts_added_from_group", len(contactsResult)).Msg("Finished fetching and filtering connections")

	return contactsResult, nil
}

// SetGoogleContactsAuthToken handles storing the Google Contacts API authentication token for a user.
func (s *server) SetGoogleContactsAuthToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		var req AuthTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		if strings.TrimSpace(req.AuthToken) == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing AuthToken in Payload"))
			return
		}

		query := "UPDATE users SET google_contacts_auth_token = $1 WHERE id = $2"
		if s.db.DriverName() == "sqlite" {
			query = "UPDATE users SET google_contacts_auth_token = ? WHERE id = ?"
		}

		result, err := s.db.Exec(query, req.AuthToken, txtid)
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to update google_contacts_auth_token")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to store auth token"))
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to check affected rows for google_contacts_auth_token update")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to confirm token storage"))
			return
		}
		if rowsAffected == 0 {
			log.Warn().Str("user_id", txtid).Msg("No user found to update google_contacts_auth_token, though middleware should ensure user exists")
			s.Respond(w, r, http.StatusNotFound, errors.New("User not found to store token"))
			return
		}

		response := map[string]string{"detail": "Auth token stored successfully"}
		responseJson, _ := json.Marshal(response)
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}

// AddContactGroupToMode handles adding contacts from a Google Contact Group to a mode.
func (s *server) AddContactGroupToMode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		var req ContactGroupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		if strings.TrimSpace(req.ModeName) == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing ModeName in Payload"))
			return
		}
		if strings.TrimSpace(req.GroupName) == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing GroupName in Payload"))
			return
		}
		if strings.TrimSpace(req.Message) == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Message in Payload"))
			return
		}

		modeName := strings.ToLower(req.ModeName)
		if !isValidModeName(modeName) { // isValidModeName will be in autoreply_handlers.go
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid ModeName: must be alphanumeric"))
			return
		}

		var googleAuthToken sql.NullString
		tokenQuery := "SELECT google_contacts_auth_token FROM users WHERE id = $1"
		if s.db.DriverName() == "sqlite" {
			tokenQuery = "SELECT google_contacts_auth_token FROM users WHERE id = ?"
		}
		err := s.db.Get(&googleAuthToken, tokenQuery, txtid)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Error().Str("user_id", txtid).Msg("User not found when trying to fetch Google Auth Token")
				s.Respond(w, r, http.StatusNotFound, errors.New("User not found"))
				return
			}
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to fetch google_contacts_auth_token")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to retrieve auth token information"))
			return
		}

		if !googleAuthToken.Valid || googleAuthToken.String == "" {
			s.Respond(w, r, http.StatusForbidden, errors.New("Google Contacts API token not configured. Please use /autoreply/contactgroupauth."))
			return
		}

		contacts, err := fetchContactsFromGoogleGroupFunc(googleAuthToken.String, req.GroupName, txtid)
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Str("groupName", req.GroupName).Msg("Error from fetchContactsFromGoogleGroup in AddContactGroupToMode")
			if strings.Contains(err.Error(), "UNAUTHENTICATED") || strings.Contains(err.Error(), "PERMISSION_DENIED") {
				s.Respond(w, r, http.StatusForbidden, errors.New("Failed to authenticate with Google Contacts API. Please check your token or re-authenticate via /autoreply/contactgroupauth."))
			} else if strings.Contains(err.Error(), "contact group '"+req.GroupName+"' not found") {
				s.Respond(w, r, http.StatusNotFound, errors.New(fmt.Sprintf("Specified contact group '%s' not found.", req.GroupName)))
			} else {
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Error processing contacts from Google group."))
			}
			return
		}

		if len(contacts) == 0 {
			response := map[string]string{"detail": fmt.Sprintf("No contacts found or processed for group '%s'.", req.GroupName)}
			responseJson, _ := json.Marshal(response)
			s.Respond(w, r, http.StatusOK, string(responseJson))
			return
		}

		var upsertQuery string
		dbType := s.db.DriverName()
		if dbType == "postgres" {
			upsertQuery = `INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message)
                           VALUES ($1, $2, $3, $4)
                           ON CONFLICT (user_id, mode_name, phone_number)
                           DO UPDATE SET message = EXCLUDED.message;`
		} else {
			upsertQuery = `INSERT OR REPLACE INTO autoreply_modes (user_id, mode_name, phone_number, message)
                           VALUES (?, ?, ?, ?);`
		}

		var processedCount, skippedCount int
		tx, err := s.db.Beginx()
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to begin transaction for AddContactGroupToMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to process contacts"))
			return
		}
		defer tx.Rollback()

		stmt, err := tx.Preparex(upsertQuery)
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to prepare statement for inserting mode autoreplies")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to process contacts"))
			return
		}
		defer stmt.Close()

		for _, contact := range contacts {
			phoneNumber, ok := contact["phoneNumber"]
			if !ok || strings.TrimSpace(phoneNumber) == "" {
				log.Warn().Str("user_id", txtid).Str("contact_name", contact["name"]).Msg("Skipping contact due to missing or empty phone number")
				skippedCount++
				continue
			}

			normalizedPhone, normErr := normalizePhoneNumber(phoneNumber)
			if normErr != nil {
				log.Warn().Err(normErr).Str("user_id", txtid).Str("original_phone", phoneNumber).Str("contact_name", contact["name"]).Msg("Skipping contact due to phone normalization error")
				skippedCount++
				continue
			}

			if _, err := stmt.Exec(txtid, modeName, normalizedPhone, req.Message); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Str("normalized_phone", normalizedPhone).Msg("Failed to upsert contact into autoreply_modes")
				skippedCount++
				continue
			}
			processedCount++
		}

		if err := tx.Commit(); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to commit transaction for AddContactGroupToMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to save contact group data"))
			return
		}

		detailMsg := fmt.Sprintf("%d contacts processed and added/updated for mode '%s'. %d contacts skipped.", processedCount, modeName, skippedCount)
		response := map[string]string{"detail": detailMsg}
		responseJson, _ := json.Marshal(response)
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}

// DeleteContactGroupFromMode handles deleting contacts from a Google Contact Group from a mode.
func (s *server) DeleteContactGroupFromMode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		var req ContactGroupDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		if strings.TrimSpace(req.ModeName) == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing ModeName in Payload"))
			return
		}
		if strings.TrimSpace(req.GroupName) == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing GroupName in Payload"))
			return
		}

		modeName := strings.ToLower(req.ModeName)
		if !isValidModeName(modeName) { // isValidModeName will be in autoreply_handlers.go
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid ModeName: must be alphanumeric"))
			return
		}

		var googleAuthToken sql.NullString
		tokenQuery := "SELECT google_contacts_auth_token FROM users WHERE id = $1"
		if s.db.DriverName() == "sqlite" {
			tokenQuery = "SELECT google_contacts_auth_token FROM users WHERE id = ?"
		}
		err := s.db.Get(&googleAuthToken, tokenQuery, txtid)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Error().Str("user_id", txtid).Msg("User not found when trying to fetch Google Auth Token for delete op")
				s.Respond(w, r, http.StatusNotFound, errors.New("User not found"))
				return
			}
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to fetch google_contacts_auth_token for delete op")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to retrieve auth token information"))
			return
		}

		if !googleAuthToken.Valid || googleAuthToken.String == "" {
			s.Respond(w, r, http.StatusForbidden, errors.New("Google Contacts API token not configured. Please use /autoreply/contactgroupauth."))
			return
		}

		contacts, err := fetchContactsFromGoogleGroupFunc(googleAuthToken.String, req.GroupName, txtid)
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Str("groupName", req.GroupName).Msg("Error from fetchContactsFromGoogleGroup in DeleteContactGroupFromMode")
			if strings.Contains(err.Error(), "UNAUTHENTICATED") || strings.Contains(err.Error(), "PERMISSION_DENIED") {
				s.Respond(w, r, http.StatusForbidden, errors.New("Failed to authenticate with Google Contacts API. Please check your token or re-authenticate via /autoreply/contactgroupauth."))
			} else if strings.Contains(err.Error(), "contact group '"+req.GroupName+"' not found") {
				s.Respond(w, r, http.StatusNotFound, errors.New(fmt.Sprintf("Specified contact group '%s' not found.", req.GroupName)))
			} else {
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Error processing contacts from Google group for deletion."))
			}
			return
		}

		if len(contacts) == 0 {
			response := map[string]string{"detail": fmt.Sprintf("No contacts found in group '%s' to process for deletion.", req.GroupName)}
			responseJson, _ := json.Marshal(response)
			s.Respond(w, r, http.StatusOK, string(responseJson))
			return
		}

		deleteQuery := "DELETE FROM autoreply_modes WHERE user_id = $1 AND mode_name = $2 AND phone_number = $3"
		if s.db.DriverName() == "sqlite" {
			deleteQuery = "DELETE FROM autoreply_modes WHERE user_id = ? AND mode_name = ? AND phone_number = ?"
		}

		var processedCount, skippedCount, actuallyDeletedCount int

		tx, err := s.db.Beginx()
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to begin transaction for DeleteContactGroupFromMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to process contacts for deletion"))
			return
		}
		defer tx.Rollback()

		stmt, err := tx.Preparex(deleteQuery)
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to prepare statement for deleting mode autoreplies")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to process contacts for deletion"))
			return
		}
		defer stmt.Close()

		for _, contact := range contacts {
			phoneNumber, ok := contact["phoneNumber"]
			if !ok || strings.TrimSpace(phoneNumber) == "" {
				log.Warn().Str("user_id", txtid).Str("contact_name", contact["name"]).Msg("Skipping contact for deletion due to missing or empty phone number")
				skippedCount++
				continue
			}

			normalizedPhone, normErr := normalizePhoneNumber(phoneNumber)
			if normErr != nil {
				log.Warn().Err(normErr).Str("user_id", txtid).Str("original_phone", phoneNumber).Str("contact_name", contact["name"]).Msg("Skipping contact for deletion due to phone normalization error")
				skippedCount++
				continue
			}

			result, err := stmt.Exec(txtid, modeName, normalizedPhone)
			if err != nil {
				log.Error().Err(err).Str("user_id", txtid).Str("normalized_phone", normalizedPhone).Msg("Failed to delete contact from autoreply_modes")
				skippedCount++
				continue
			}
			processedCount++
			rowsAffected, _ := result.RowsAffected()
			if rowsAffected > 0 {
				actuallyDeletedCount++
			}
		}

		if err := tx.Commit(); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to commit transaction for DeleteContactGroupFromMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to save changes for contact group deletion"))
			return
		}

		detailMsg := fmt.Sprintf("%d contacts from group '%s' processed for deletion from mode '%s'. %d entries actually deleted. %d contacts skipped.", processedCount, req.GroupName, modeName, actuallyDeletedCount, skippedCount)
		response := map[string]string{"detail": detailMsg}
		responseJson, _ := json.Marshal(response)
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}
