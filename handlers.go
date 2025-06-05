package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io" // Added this line
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/nfnt/resize"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/vincent-petithory/dataurl"
	"go.mau.fi/whatsmeow"

	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"

	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"
)

type AutoReplyRequest struct {
	Phone string `json:"Phone"`
	Body  string `json:"Body"`
}

type AutoReplyEntry struct {
	Phone      string     `json:"phone"`
	Body       string     `json:"body"`
	LastSentAt *time.Time `json:"last_sent_at,omitempty"` // Use a pointer to handle NULL values, omitempty to hide if NULL
}

type DeleteAutoReplyRequest struct {
	Phone string `json:"Phone"`
}

// Structs for Mode Autoreply functionality
type ModeAutoreplyRequest struct {
	ModeName string `json:"ModeName"`
	Phone    string `json:"Phone"`
	Message  string `json:"Message"`
}

type ModeAutoreplyDeleteRequest struct {
	ModeName string `json:"ModeName"`
	Phone    string `json:"Phone,omitempty"` // Optional: if not provided, delete all for mode
}

type EnableModeRequest struct {
	ModeName string `json:"ModeName"`
}

type DisableModeRequest struct {
	ModeName string `json:"ModeName"`
}

type ModeAutoreplyEntry struct {
	ModeName string `json:"ModeName"`
	Phone    string `json:"Phone"`
	Message  string `json:"Message"`
}

// AuthTokenRequest defines the structure for the /autoreply/contactgroupauth endpoint
type AuthTokenRequest struct {
	AuthToken string `json:"AuthToken"`
}

// ContactGroupRequest defines the structure for the /autoreply/contactgroup endpoint
type ContactGroupRequest struct {
	ModeName  string `json:"ModeName"`
	GroupName string `json:"GroupName"`
	Message   string `json:"Message"`
}

// ContactGroupDeleteRequest defines the structure for the DELETE /autoreply/contactgroup endpoint
type ContactGroupDeleteRequest struct {
	ModeName  string `json:"ModeName"`
	GroupName string `json:"GroupName"`
}

type Values struct {
	m map[string]string
}

func (v Values) Get(key string) string {
	return v.m[key]
}

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


// Structs for Google People API responses
type GoogleContactGroup struct {
	ResourceName  string `json:"resourceName"`
	Name          string `json:"name"`
	FormattedName string `json:"formattedName"`
	MemberCount   int    `json:"memberCount"`
}

type GoogleContactGroupListResponse struct {
	ContactGroups []GoogleContactGroup `json:"contactGroups"`
	NextPageToken string             `json:"nextPageToken"`
}

type GooglePersonName struct {
	DisplayName string `json:"displayName"`
}

type GooglePhoneNumber struct {
	Value         string `json:"value"`
	CanonicalForm string `json:"canonicalForm"`
}

type GoogleContactGroupMembership struct {
	ContactGroupResourceName string `json:"contactGroupResourceName"`
}

type GoogleMembership struct {
	ContactGroupMembership GoogleContactGroupMembership `json:"contactGroupMembership"`
}

type GooglePerson struct {
	ResourceName string              `json:"resourceName"`
	Names        []GooglePersonName    `json:"names"`
	PhoneNumbers []GooglePhoneNumber   `json:"phoneNumbers"`
	Memberships  []GoogleMembership    `json:"memberships"`
}

type GoogleConnectionsListResponse struct {
	Connections   []GooglePerson `json:"connections"`
	NextPageToken string       `json:"nextPageToken"`
	TotalItems    int          `json:"totalItems"`
}

// GoogleApiErrorDetail provides structure for the "error" field in Google API error responses.
type GoogleApiErrorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// GoogleApiError provides structure for Google API error responses.
type GoogleApiError struct {
	Error GoogleApiErrorDetail `json:"error"`
}

var fetchContactsFromGoogleGroupFunc = func(authToken string, groupName string, forUserLog string) ([]map[string]string, error) {
	log.Info().Str("user_id", forUserLog).Str("groupName", groupName).Msg("Starting to fetch contacts from Google Group (REAL IMPLEMENTATION)")

	httpClient := http.DefaultClient // Or a custom client if needed

	// 1. Get Target Group Resource Name
	var targetGroupResourceName string
	var pageToken string
	processedGroups := 0

	log.Debug().Str("user_id", forUserLog).Msg("Fetching contact groups from Google People API")
	for {
		groupsURL := "https://people.googleapis.com/v1/contactGroups?pageSize=100" // Max pageSize is 1000, but 100 is fine for most cases
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
			break // Found the group
		}
		pageToken = groupListResp.NextPageToken
		if pageToken == "" {
			break // No more pages
		}
	}
	log.Debug().Str("user_id", forUserLog).Int("total_groups_checked", processedGroups).Msg("Finished checking contact groups")


	if targetGroupResourceName == "" {
		return nil, fmt.Errorf("contact group '%s' not found for user %s", groupName, forUserLog)
	}

	// 2. Get Contacts in the Target Group
	var contactsResult []map[string]string
	pageToken = "" // Reset for connections request
	processedConnections := 0

	log.Debug().Str("user_id", forUserLog).Str("groupResourceName", targetGroupResourceName).Msg("Fetching connections for the target group from Google People API")
	for {
		connectionsURL := "https://people.googleapis.com/v1/people/me/connections?personFields=names,phoneNumbers,memberships&pageSize=100" // Max pageSize 1000
		if pageToken != "" {
			connectionsURL += "&pageToken=" + pageToken
		}
		// No direct server-side filtering by contactGroupResourceName for people.me.connections
		// We must fetch all connections and filter client-side by membership.

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
					// Prefer CanonicalForm if available, otherwise Value
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
			break // No more pages
		}
	}
	log.Info().Str("user_id", forUserLog).Int("total_connections_checked", processedConnections).Int("contacts_added_from_group", len(contactsResult)).Msg("Finished fetching and filtering connections")

	return contactsResult, nil
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
		if !isValidModeName(modeName) {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid ModeName: must be alphanumeric"))
			return
		}

		// 1. Retrieve Auth Token
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

		// 2. Fetch contacts
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
			// Respond with a success=true but a detail message, not an error object for Respond()
			response := map[string]string{"detail": fmt.Sprintf("No contacts found or processed for group '%s'.", req.GroupName)}
			responseJson, _ := json.Marshal(response)
			s.Respond(w, r, http.StatusOK, string(responseJson))
			return
		}

		// 3. Process contacts and add to autoreply_modes
		var upsertQuery string
		dbType := s.db.DriverName()
		if dbType == "postgres" {
			upsertQuery = `INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message)
                           VALUES ($1, $2, $3, $4)
                           ON CONFLICT (user_id, mode_name, phone_number)
                           DO UPDATE SET message = EXCLUDED.message;`
		} else { // sqlite
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
		defer tx.Rollback() // Rollback if not committed

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
				// Decide if one failure should stop all, for now, we'll skip and count
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

// DeleteContactGroupFromMode handles deleting contacts from a (simulated) Google Contact Group from a mode.
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
		if !isValidModeName(modeName) {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid ModeName: must be alphanumeric"))
			return
		}

		// 1. Retrieve Auth Token
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

		// 2. Fetch contacts - same function as Add
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

		// 3. Process contacts for deletion from autoreply_modes
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
				// Decide if one failure should stop all, for now, we'll skip and count
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

var messageTypes = []string{"Message", "ReadReceipt", "Presence", "HistorySync", "ChatPresence", "All"}

func (s *server) authadmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != *adminToken {
			s.Respond(w, r, http.StatusUnauthorized, errors.New("Unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) authalice(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var ctx context.Context
		txtid := ""
		name := ""
		webhook := ""
		jid := ""
		events := ""
		proxy_url := ""
		qrcode := ""

		// Get token from headers or uri parameters
		token := r.Header.Get("token")
		if token == "" {
			token = strings.Join(r.URL.Query()["token"], "")
		}

		myuserinfo, found := userinfocache.Get(token)
		if !found {
			log.Info().Msg("Looking for user information in DB")
			// Checks DB from matching user and store user values in context
			rows, err := s.db.Query("SELECT id,name,webhook,jid,events,proxy_url,qrcode FROM users WHERE token=$1 LIMIT 1", token)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, err)
				return
			}
			defer rows.Close()
			for rows.Next() {
				err = rows.Scan(&txtid, &name, &webhook, &jid, &events, &proxy_url, &qrcode)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, err)
					return
				}
				v := Values{map[string]string{
					"Id":      txtid,
					"Name":    name,
					"Jid":     jid,
					"Webhook": webhook,
					"Token":   token,
					"Proxy":   proxy_url,
					"Events":  events,
					"Qrcode":  qrcode,
				}}

				userinfocache.Set(token, v, cache.NoExpiration)
				log.Info().Str("name", name).Msg("User info name from DB")
				ctx = context.WithValue(r.Context(), "userinfo", v)
			}
		} else {
			ctx = context.WithValue(r.Context(), "userinfo", myuserinfo)
			log.Info().Str("name", myuserinfo.(Values).Get("name")).Msg("User info name from Cache")
			txtid = myuserinfo.(Values).Get("Id")
		}

		if txtid == "" {
			s.Respond(w, r, http.StatusUnauthorized, errors.New("Unauthorized"))
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Connects to Whatsapp Servers
func (s *server) Connect() http.HandlerFunc {

	type connectStruct struct {
		Subscribe []string
		Immediate bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		webhook := r.Context().Value("userinfo").(Values).Get("Webhook")
		jid := r.Context().Value("userinfo").(Values).Get("Jid")
		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		token := r.Context().Value("userinfo").(Values).Get("Token")
		eventstring := ""

		// Decodes request BODY looking for events to subscribe
		decoder := json.NewDecoder(r.Body)
		var t connectStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if clientManager.GetWhatsmeowClient(txtid) != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Already Connected"))
			return
		} else {

			var subscribedEvents []string
			if len(t.Subscribe) < 1 {
				if !Find(subscribedEvents, "All") {
					subscribedEvents = append(subscribedEvents, "All")
				}
			} else {
				for _, arg := range t.Subscribe {
					if !Find(messageTypes, arg) {
						log.Warn().Str("Type", arg).Msg("Message type discarded")
						continue
					}
					if !Find(subscribedEvents, arg) {
						subscribedEvents = append(subscribedEvents, arg)
					}
				}
			}
			eventstring = strings.Join(subscribedEvents, ",")
			_, err = s.db.Exec("UPDATE users SET events=$1 WHERE id=$2", eventstring, txtid)
			if err != nil {
				log.Warn().Msg("Could not set events in users table")
			}
			log.Info().Str("events", eventstring).Msg("Setting subscribed events")
			v := updateUserInfo(r.Context().Value("userinfo"), "Events", eventstring)
			userinfocache.Set(token, v, cache.NoExpiration)

			log.Info().Str("jid", jid).Msg("Attempt to connect")
			killchannel[txtid] = make(chan bool)
			go s.startClient(txtid, jid, token, subscribedEvents)

			if t.Immediate == false {
				log.Warn().Msg("Waiting 10 seconds")
				time.Sleep(10000 * time.Millisecond)

				if clientManager.GetWhatsmeowClient(txtid) != nil {
					if !clientManager.GetWhatsmeowClient(txtid).IsConnected() {
						s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to Connect"))
						return
					}
				} else {
					s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to Connect"))
					return
				}
			}
		}

		response := map[string]interface{}{"webhook": webhook, "jid": jid, "events": eventstring, "details": "Connected!"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
			return
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
			return
		}
	}
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
			// This case should ideally not happen if txtid is always valid from middleware,
			// but good to be aware of. It means the user ID didn't match any row.
			log.Warn().Str("user_id", txtid).Msg("No user found to update google_contacts_auth_token, though middleware should ensure user exists")
			s.Respond(w, r, http.StatusNotFound, errors.New("User not found to store token"))
			return
		}

		response := map[string]string{"detail": "Auth token stored successfully"}
		responseJson, _ := json.Marshal(response)
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}

// AddAutoReply handles adding a new auto-reply entry for a user.
func (s *server) AddAutoReply() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		var req AutoReplyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		if req.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}
		if req.Body == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Body in Payload"))
			return
		}

		newId, err := GenerateRandomID() // Assuming GenerateRandomID is accessible from migrations.go
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate random ID for auto-reply")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to create auto-reply entry"))
			return
		}

		// Set last_sent_at to NULL (or zero-value for time.Time which translates to NULL for nullable timestamp)
		_, err = s.db.Exec("INSERT INTO autoreplies (id, user_id, phone_number, reply_body, last_sent_at) VALUES ($1, $2, $3, $4, $5)", newId, txtid, req.Phone, req.Body, nil)
		if err != nil {
			// Check for unique constraint violation (specific error code might depend on DB: PostgreSQL uses "23505")
			// This is a simplified check; a more robust way involves checking pq.Error.Code or sqlite3.ErrConstraintUnique
			if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
				s.Respond(w, r, http.StatusConflict, errors.New("Auto-reply for this phone number already exists for the user"))
				return
			}
			log.Error().Err(err).Str("user_id", txtid).Str("phone", req.Phone).Msg("Failed to add auto-reply")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to add auto-reply"))
			return
		}

		response := map[string]string{"detail": "Auto-reply added successfully", "id": newId}
		responseJson, err := json.Marshal(response)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal success response for AddAutoReply")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to create auto-reply entry"))
			return
		}
		s.Respond(w, r, http.StatusCreated, string(responseJson))
	}
}

// GetAutoReplies handles fetching all auto-reply entries for a user.
func (s *server) GetAutoReplies() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		rows, err := s.db.Query("SELECT phone_number, reply_body, last_sent_at FROM autoreplies WHERE user_id = $1", txtid)
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to query auto-replies")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to retrieve auto-replies"))
			return
		}
		defer rows.Close()

		var replies []AutoReplyEntry
		for rows.Next() {
			var entry AutoReplyEntry
			var lastSentAt sql.NullTime // Use sql.NullTime to scan nullable timestamp
			if err := rows.Scan(&entry.Phone, &entry.Body, &lastSentAt); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Msg("Failed to scan auto-reply row")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to process auto-reply data"))
				return
			}
			if lastSentAt.Valid {
				entry.LastSentAt = &lastSentAt.Time // Convert to *time.Time if valid
			} else {
				entry.LastSentAt = nil
			}
			replies = append(replies, entry)
		}

		if err = rows.Err(); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Error iterating auto-reply rows")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to read auto-replies"))
			return
		}

		responseJson, err := json.Marshal(replies)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal auto-replies response")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to format auto-replies response"))
			return
		}
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}

// DeleteAutoReply handles deleting an auto-reply entry for a user.
func (s *server) DeleteAutoReply() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		var req DeleteAutoReplyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		if req.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		result, err := s.db.Exec("DELETE FROM autoreplies WHERE user_id = $1 AND phone_number = $2", txtid, req.Phone)
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Str("phone", req.Phone).Msg("Failed to delete auto-reply")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to delete auto-reply"))
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Str("phone", req.Phone).Msg("Failed to check affected rows after delete")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to confirm deletion status"))
			return
		}

		if rowsAffected == 0 {
			s.Respond(w, r, http.StatusNotFound, errors.New("Auto-reply not found for this user and phone number"))
			return
		}

		response := map[string]string{"detail": "Auto-reply deleted successfully"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal success response for DeleteAutoReply")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to process deletion confirmation")) // Should ideally not happen
			return
		}
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}

// isValidModeName checks if the mode name is purely alphanumeric.
func isValidModeName(modeName string) bool {
	if modeName == "" {
		return false
	}
	// Regex for alphanumeric only
	// For a more robust solution, consider using a proper regex library if more complex rules are needed.
	// This basic check iterates through runes.
	for _, r := range modeName {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// AddModeAutoreply handles adding or updating an autoreply message for a specific mode.
func (s *server) AddModeAutoreply() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		var req ModeAutoreplyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		modeName := strings.ToLower(req.ModeName)
		if !isValidModeName(modeName) {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid ModeName: must be alphanumeric"))
			return
		}

		if req.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}
		if req.Message == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Message in Payload"))
			return
		}

		var query string
		dbType := s.db.DriverName()
		if dbType == "postgres" {
			query = `INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (user_id, mode_name, phone_number)
                     DO UPDATE SET message = EXCLUDED.message;`
		} else { // sqlite
			query = `INSERT OR REPLACE INTO autoreply_modes (user_id, mode_name, phone_number, message)
                     VALUES (?, ?, ?, ?);`
		}

		_, err := s.db.Exec(query, txtid, modeName, req.Phone, req.Message)
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Str("mode_name", modeName).Msg("Failed to add/update mode autoreply")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to save mode autoreply"))
			return
		}

		response := map[string]string{"detail": "Mode autoreply added/updated successfully"}
		responseJson, _ := json.Marshal(response)
		s.Respond(w, r, http.StatusCreated, string(responseJson))
	}
}

// DeleteModeAutoreply handles deleting autoreply messages for a specific mode.
func (s *server) DeleteModeAutoreply() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		var req ModeAutoreplyDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		modeName := strings.ToLower(req.ModeName)
		if !isValidModeName(modeName) {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid ModeName: must be alphanumeric"))
			return
		}

		var result sql.Result
		var err error

		if req.Phone != "" {
			query := "DELETE FROM autoreply_modes WHERE user_id = $1 AND mode_name = $2 AND phone_number = $3"
			if s.db.DriverName() == "sqlite" {
				query = "DELETE FROM autoreply_modes WHERE user_id = ? AND mode_name = ? AND phone_number = ?"
			}
			result, err = s.db.Exec(query, txtid, modeName, req.Phone)
		} else {
			query := "DELETE FROM autoreply_modes WHERE user_id = $1 AND mode_name = $2"
			if s.db.DriverName() == "sqlite" {
				query = "DELETE FROM autoreply_modes WHERE user_id = ? AND mode_name = ?"
			}
			result, err = s.db.Exec(query, txtid, modeName)
		}

		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Str("mode_name", modeName).Msg("Failed to delete mode autoreply")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to delete mode autoreply"))
			return
		}

		rowsAffected, _ := result.RowsAffected()
		detailMsg := fmt.Sprintf("%d autoreply entry(s) deleted for mode '%s'", rowsAffected, modeName)
		if rowsAffected == 0 {
			detailMsg = fmt.Sprintf("No autoreply entries found or deleted for mode '%s'", modeName)
		}

		response := map[string]string{"detail": detailMsg}
		responseJson, _ := json.Marshal(response)
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}

// GetModeAutoreplies handles fetching autoreply messages, optionally filtered by mode.
func (s *server) GetModeAutoreplies() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		modeNameParam := r.URL.Query().Get("modeName")

		var rows *sql.Rows
		var err error

		if modeNameParam != "" {
			modeName := strings.ToLower(modeNameParam)
			if !isValidModeName(modeName) {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid modeName parameter: must be alphanumeric"))
				return
			}
			query := "SELECT mode_name, phone_number, message FROM autoreply_modes WHERE user_id = $1 AND mode_name = $2"
			if s.db.DriverName() == "sqlite" {
				query = "SELECT mode_name, phone_number, message FROM autoreply_modes WHERE user_id = ? AND mode_name = ?"
			}
			rows, err = s.db.Query(query, txtid, modeName)
		} else {
			query := "SELECT mode_name, phone_number, message FROM autoreply_modes WHERE user_id = $1"
			if s.db.DriverName() == "sqlite" {
				query = "SELECT mode_name, phone_number, message FROM autoreply_modes WHERE user_id = ?"
			}
			rows, err = s.db.Query(query, txtid)
		}

		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to query mode autoreplies")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to retrieve mode autoreplies"))
			return
		}
		defer rows.Close()

		var entries []ModeAutoreplyEntry
		for rows.Next() {
			var entry ModeAutoreplyEntry
			if err := rows.Scan(&entry.ModeName, &entry.Phone, &entry.Message); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Msg("Failed to scan mode autoreply row")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to process mode autoreply data"))
				return
			}
			entries = append(entries, entry)
		}

		if err = rows.Err(); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Error iterating mode autoreply rows")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to read mode autoreplies"))
			return
		}

		responseJson, _ := json.Marshal(entries)
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}

// EnableMode activates a specific autoreply mode for the user.
func (s *server) EnableMode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		var req EnableModeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		modeName := strings.ToLower(req.ModeName)
		if !isValidModeName(modeName) {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid ModeName: must be alphanumeric"))
			return
		}

		dbType := s.db.DriverName()

		// Start transaction
		tx, err := s.db.Beginx()
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to begin transaction for EnableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode"))
			return
		}
		defer tx.Rollback() // Rollback if not committed

		// 1. Clear current autoreply list for the user
		clearAutorepliesQuery := "DELETE FROM autoreplies WHERE user_id = $1"
		if dbType == "sqlite" {
			clearAutorepliesQuery = "DELETE FROM autoreplies WHERE user_id = ?"
		}
		if _, err := tx.Exec(clearAutorepliesQuery, txtid); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to clear autoreplies for EnableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode (clear old)"))
			return
		}

		// 2. Fetch new numbers and messages for the mode
		type modeEntry struct {
			PhoneNumber string `db:"phone_number"`
			Message     string `db:"message"`
		}
		var entriesToActivate []modeEntry
		fetchModeEntriesQuery := "SELECT phone_number, message FROM autoreply_modes WHERE user_id = $1 AND mode_name = $2"
		if dbType == "sqlite" {
			fetchModeEntriesQuery = "SELECT phone_number, message FROM autoreply_modes WHERE user_id = ? AND mode_name = ?"
		}
		err = tx.Select(&entriesToActivate, fetchModeEntriesQuery, txtid, modeName)
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Str("mode_name", modeName).Msg("Failed to fetch mode entries for EnableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode (fetch new)"))
			return
		}

		if len(entriesToActivate) == 0 {
             log.Warn().Str("user_id", txtid).Str("mode_name", modeName).Msg("EnableMode called for a mode with no entries or mode does not exist")
        }


		// 3. Populate autoreply list
		insertAutoreplyQuery := "INSERT INTO autoreplies (id, user_id, phone_number, reply_body, last_sent_at) VALUES ($1, $2, $3, $4, NULL)"
		if dbType == "sqlite" {
			insertAutoreplyQuery = "INSERT INTO autoreplies (id, user_id, phone_number, reply_body, last_sent_at) VALUES (?, ?, ?, ?, NULL)"
		}
		stmt, err := tx.Preparex(insertAutoreplyQuery)
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to prepare statement for inserting autoreplies")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode (prepare insert)"))
			return
		}
		defer stmt.Close()

		for _, entry := range entriesToActivate {
			newId, idErr := GenerateRandomID()
			if idErr != nil {
				log.Error().Err(idErr).Msg("Failed to generate random ID for autoreply entry in EnableMode")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode (generate id)"))
				return
			}
			if _, err := stmt.Exec(newId, txtid, entry.PhoneNumber, entry.Message); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Msg("Failed to insert autoreply entry in EnableMode")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode (insert new)"))
				return
			}
		}

		// 4. Update active mode
		var updateActiveModeQuery string
		if dbType == "postgres" {
			updateActiveModeQuery = `INSERT INTO active_mode (user_id, current_mode_name) VALUES ($1, $2)
                                 ON CONFLICT(user_id) DO UPDATE SET current_mode_name = EXCLUDED.current_mode_name;`
		} else { // sqlite
			updateActiveModeQuery = `INSERT OR REPLACE INTO active_mode (user_id, current_mode_name) VALUES (?, ?);`
		}
		if _, err := tx.Exec(updateActiveModeQuery, txtid, modeName); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Str("mode_name", modeName).Msg("Failed to update active_mode for EnableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode (update active)"))
			return
		}

		// Commit transaction
		if err := tx.Commit(); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to commit transaction for EnableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode (commit)"))
			return
		}

		detailMsg := fmt.Sprintf("Mode '%s' enabled successfully. %d autoreplies activated.", modeName, len(entriesToActivate))
		response := map[string]string{"detail": detailMsg}
		responseJson, _ := json.Marshal(response)
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}

// DisableMode deactivates a specific autoreply mode if it's currently active.
func (s *server) DisableMode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		var req DisableModeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		modeName := strings.ToLower(req.ModeName)
		if !isValidModeName(modeName) {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid ModeName: must be alphanumeric"))
			return
		}

		dbType := s.db.DriverName()

		// Start transaction
		tx, err := s.db.Beginx()
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to begin transaction for DisableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to disable mode"))
			return
		}
		defer tx.Rollback()

		// Check if it's the active mode
		var currentActiveMode sql.NullString
		getActiveModeQuery := "SELECT current_mode_name FROM active_mode WHERE user_id = $1"
		if dbType == "sqlite" {
			getActiveModeQuery = "SELECT current_mode_name FROM active_mode WHERE user_id = ?"
		}
		err = tx.Get(&currentActiveMode, getActiveModeQuery, txtid)
		if err != nil && err != sql.ErrNoRows {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to query active_mode for DisableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to disable mode (check active)"))
			return
		}

		if currentActiveMode.Valid && currentActiveMode.String == modeName {
			// Clear autoreplies
			clearAutorepliesQuery := "DELETE FROM autoreplies WHERE user_id = $1"
			if dbType == "sqlite" {
				clearAutorepliesQuery = "DELETE FROM autoreplies WHERE user_id = ?"
			}
			if _, err := tx.Exec(clearAutorepliesQuery, txtid); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Msg("Failed to clear autoreplies for DisableMode")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to disable mode (clear replies)"))
				return
			}

			// Update active_mode to NULL
			updateActiveModeQuery := "UPDATE active_mode SET current_mode_name = NULL WHERE user_id = $1"
			if dbType == "sqlite" {
				updateActiveModeQuery = "UPDATE active_mode SET current_mode_name = NULL WHERE user_id = ?"
			}
			if _, err := tx.Exec(updateActiveModeQuery, txtid); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Msg("Failed to set active_mode to NULL for DisableMode")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to disable mode (set null)"))
				return
			}

			// Commit transaction
			if err := tx.Commit(); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Msg("Failed to commit transaction for DisableMode")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to disable mode (commit)"))
				return
			}
			response := map[string]string{"detail": fmt.Sprintf("Mode '%s' disabled successfully.", modeName)}
			responseJson, _ := json.Marshal(response)
			s.Respond(w, r, http.StatusOK, string(responseJson))
		} else {
			// Mode was not active, or no mode was active. Still a success from client perspective.
			// No need to commit as no changes were made in this path.
			response := map[string]string{"detail": fmt.Sprintf("Mode '%s' was not active or does not exist. No changes made.", modeName)}
			responseJson, _ := json.Marshal(response)
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// GetCurrentMode retrieves the currently active autoreply mode for the user.
func (s *server) GetCurrentMode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		dbType := s.db.DriverName()

		var currentMode sql.NullString
		query := "SELECT current_mode_name FROM active_mode WHERE user_id = $1"
		if dbType == "sqlite" {
			query = "SELECT current_mode_name FROM active_mode WHERE user_id = ?"
		}
		err := s.db.Get(&currentMode, query, txtid)

		if err != nil && err != sql.ErrNoRows {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to get current mode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to retrieve current mode"))
			return
		}

		var modeNameStr string
		if currentMode.Valid {
			modeNameStr = currentMode.String
		} else {
			modeNameStr = "" // Or null, depending on desired JSON output for no active mode
		}

		response := map[string]interface{}{"current_mode_name": modeNameStr}
		if !currentMode.Valid {
             response = map[string]interface{}{"current_mode_name": nil}
        }
		responseJson, _ := json.Marshal(response)
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}

// ClearModes deactivates any active mode and clears all autoreplies for the user.
func (s *server) ClearModes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		dbType := s.db.DriverName()

		tx, err := s.db.Beginx()
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to begin transaction for ClearModes")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to clear modes"))
			return
		}
		defer tx.Rollback()

		// Clear autoreplies
		clearAutorepliesQuery := "DELETE FROM autoreplies WHERE user_id = $1"
		if dbType == "sqlite" {
			clearAutorepliesQuery = "DELETE FROM autoreplies WHERE user_id = ?"
		}
		if _, err := tx.Exec(clearAutorepliesQuery, txtid); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to clear autoreplies for ClearModes")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to clear modes (clear replies)"))
			return
		}

		// Update active_mode to NULL
		// Ensure row exists for user before updating, or use INSERT ON CONFLICT for active_mode as well
		var updateActiveModeQuery string
		if dbType == "postgres" {
			updateActiveModeQuery = `INSERT INTO active_mode (user_id, current_mode_name) VALUES ($1, NULL)
                                 ON CONFLICT(user_id) DO UPDATE SET current_mode_name = NULL;`
		} else { // sqlite
			// Check if user exists in active_mode, if not, insert. Otherwise, update.
			// This is safer than just UPDATE if a user might not have an entry yet.
			updateActiveModeQuery = `INSERT OR REPLACE INTO active_mode (user_id, current_mode_name)
                                     VALUES (?, (SELECT current_mode_name FROM active_mode WHERE user_id = ?));` // Keep existing if any, then set to NULL
            // Simpler: Just ensure it's NULL. If the row doesn't exist, this is fine. If it does, it sets to NULL.
            // However, to ensure the row exists for future GetCurrentMode calls to not return ErrNoRows (unless that's desired),
            // an UPSERT type logic is better.
            updateActiveModeQuery = `INSERT INTO active_mode (user_id, current_mode_name) VALUES (?, NULL)
                                     ON CONFLICT(user_id) DO UPDATE SET current_mode_name = NULL;` // For SQLite 3.24+
            // For older SQLite, might need:
            // _, err = tx.Exec("UPDATE active_mode SET current_mode_name = NULL WHERE user_id = ?", txtid)
            // if err == nil { /* check rows affected, if 0 then insert */ }
            // For simplicity and matching PostgreSQL, using the ON CONFLICT approach for SQLite too, assuming modern version.
		}
        // Corrected SQLite strategy for ClearModes:
        // Ensure a row for the user exists in active_mode and set its current_mode_name to NULL.
        if dbType == "sqlite" {
             // First, try to update. If no rows are affected, it means the user might not have an entry.
            res, err_update := tx.Exec("UPDATE active_mode SET current_mode_name = NULL WHERE user_id = ?", txtid)
            if err_update != nil {
                log.Error().Err(err_update).Str("user_id", txtid).Msg("Failed to update active_mode to NULL for ClearModes (SQLite)")
                s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to clear modes (set null)"))
                return
            }
            rowsAffected, _ := res.RowsAffected()
            if rowsAffected == 0 {
                // No existing row, so insert one with NULL mode_name.
                _, err_insert := tx.Exec("INSERT INTO active_mode (user_id, current_mode_name) VALUES (?, NULL)", txtid)
                if err_insert != nil {
                    log.Error().Err(err_insert).Str("user_id", txtid).Msg("Failed to insert into active_mode for ClearModes (SQLite)")
                    s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to clear modes (insert null)"))
                    return
                }
            }
        } else { // PostgreSQL
            if _, err := tx.Exec(updateActiveModeQuery, txtid); err != nil {
                log.Error().Err(err).Str("user_id", txtid).Msg("Failed to set active_mode to NULL for ClearModes (Postgres)")
                s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to clear modes (set null)"))
                return
            }
        }


		if err := tx.Commit(); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to commit transaction for ClearModes")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to clear modes (commit)"))
			return
		}

		response := map[string]string{"detail": "All modes cleared and current mode deactivated successfully."}
		responseJson, _ := json.Marshal(response)
		s.Respond(w, r, http.StatusOK, string(responseJson))
	}
}


// Disconnects from Whatsapp websocket, does not log out device
func (s *server) Disconnect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		jid := r.Context().Value("userinfo").(Values).Get("Jid")
		token := r.Context().Value("userinfo").(Values).Get("Token")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}
		if clientManager.GetWhatsmeowClient(txtid).IsConnected() == true {
			//if clientManager.GetWhatsmeowClient(txtid).IsLoggedIn() == true {
			log.Info().Str("jid", jid).Msg("Disconnection successfull")
			_, err := s.db.Exec("UPDATE users SET connected=0,events=$1 WHERE id=$2", "", txtid)
			if err != nil {
				log.Warn().Str("txtid", txtid).Msg("Could not set events in users table")
			}
			log.Info().Str("txtid", txtid).Msg("Update DB on disconnection")
			v := updateUserInfo(r.Context().Value("userinfo"), "Events", "")
			userinfocache.Set(token, v, cache.NoExpiration)

			response := map[string]interface{}{"Details": "Disconnected"}
			responseJson, err := json.Marshal(response)

			clientManager.DeleteWhatsmeowClient(txtid) // mameluco
			killchannel[txtid] <- true

			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, err)
			} else {
				s.Respond(w, r, http.StatusOK, string(responseJson))
			}
			return
			//} else {
			//	log.Warn().Str("jid", jid).Msg("Ignoring disconnect as it was not connected")
			//	s.Respond(w, r, http.StatusInternalServerError, errors.New("Cannot disconnect because it is not logged in"))
			//	return
			//}
		} else {
			log.Warn().Str("jid", jid).Msg("Ignoring disconnect as it was not connected")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Cannot disconnect because it is not logged in"))
			return
		}
	}
}

// Gets WebHook
func (s *server) GetWebhook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		webhook := ""
		events := ""
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		rows, err := s.db.Query("SELECT webhook,events FROM users WHERE id=$1 LIMIT 1", txtid)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not get webhook: %v", err)))
			return
		}
		defer rows.Close()
		for rows.Next() {
			err = rows.Scan(&webhook, &events)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not get webhook: %s", fmt.Sprintf("%s", err))))
				return
			}
		}
		err = rows.Err()
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not get webhook: %s", fmt.Sprintf("%s", err))))
			return
		}

		eventarray := strings.Split(events, ",")

		response := map[string]interface{}{"webhook": webhook, "subscribe": eventarray}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// DeleteWebhook removes the webhook and clears events for a user
func (s *server) DeleteWebhook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		token := r.Context().Value("userinfo").(Values).Get("Token")

		// Update the database to remove the webhook and clear events
		_, err := s.db.Exec("UPDATE users SET webhook='', events='' WHERE id=$1", txtid)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not delete webhook: %v", err)))
			return
		}

		// Update the user info cache
		v := updateUserInfo(r.Context().Value("userinfo"), "Webhook", "")
		v = updateUserInfo(v, "Events", "")
		userinfocache.Set(token, v, cache.NoExpiration)

		response := map[string]interface{}{"Details": "Webhook and events deleted successfully"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// UpdateWebhook updates the webhook URL and events for a user
func (s *server) UpdateWebhook() http.HandlerFunc {
	type updateWebhookStruct struct {
		WebhookURL string   `json:"webhook"`
		Events     []string `json:"events,omitempty"`
		Active     bool     `json:"active"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		token := r.Context().Value("userinfo").(Values).Get("Token")

		decoder := json.NewDecoder(r.Body)
		var t updateWebhookStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		webhook := t.WebhookURL

		var eventstring string
		var validEvents []string
		for _, event := range t.Events {
			if !Find(messageTypes, event) {
				log.Warn().Str("Type", event).Msg("Message type discarded")
				continue
			}
			validEvents = append(validEvents, event)
		}
		eventstring = strings.Join(validEvents, ",")
		if eventstring == "," || eventstring == "" {
			eventstring = "All"
		}

		if !t.Active {
			webhook = ""
			eventstring = ""
		}

		if len(t.Events) > 0 {
			_, err = s.db.Exec("UPDATE users SET webhook=$1, events=$2 WHERE id=$3", webhook, eventstring, txtid)
		} else {
			// Update only webhook
			_, err = s.db.Exec("UPDATE users SET webhook=$1 WHERE id=$2", webhook, txtid)
		}

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not update webhook: %v", err)))
			return
		}

		v := updateUserInfo(r.Context().Value("userinfo"), "Webhook", webhook)
		v = updateUserInfo(v, "Events", eventstring)
		userinfocache.Set(token, v, cache.NoExpiration)

		response := map[string]interface{}{"webhook": webhook, "events": t.Events, "active": t.Active}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// SetWebhook sets the webhook URL and events for a user
func (s *server) SetWebhook() http.HandlerFunc {
	type webhookStruct struct {
		WebhookURL string   `json:"webhookurl"`
		Events     []string `json:"events,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		token := r.Context().Value("userinfo").(Values).Get("Token")

		decoder := json.NewDecoder(r.Body)
		var t webhookStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		webhook := t.WebhookURL

		// If events are provided, validate them
		var eventstring string
		if len(t.Events) > 0 {
			var validEvents []string
			for _, event := range t.Events {
				if !Find(messageTypes, event) {
					log.Warn().Str("Type", event).Msg("Message type discarded")
					continue
				}
				validEvents = append(validEvents, event)
			}
			eventstring = strings.Join(validEvents, ",")
			if eventstring == "," || eventstring == "" {
				eventstring = "All"
			}

			// Update both webhook and events
			_, err = s.db.Exec("UPDATE users SET webhook=$1, events=$2 WHERE id=$3", webhook, eventstring, txtid)
		} else {
			// Update only webhook
			_, err = s.db.Exec("UPDATE users SET webhook=$1 WHERE id=$2", webhook, txtid)
		}

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not set webhook: %v", err)))
			return
		}

		v := updateUserInfo(r.Context().Value("userinfo"), "Webhook", webhook)
		v = updateUserInfo(v, "Events", eventstring)
		userinfocache.Set(token, v, cache.NoExpiration)

		response := map[string]interface{}{"webhook": webhook}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// Gets QR code encoded in Base64
func (s *server) GetQR() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		code := ""

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		} else {
			if clientManager.GetWhatsmeowClient(txtid).IsConnected() == false {
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Not connected"))
				return
			}
			rows, err := s.db.Query("SELECT qrcode AS code FROM users WHERE id=$1 LIMIT 1", txtid)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, err)
				return
			}
			defer rows.Close()
			for rows.Next() {
				err = rows.Scan(&code)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, err)
					return
				}
			}
			err = rows.Err()
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, err)
				return
			}
			if clientManager.GetWhatsmeowClient(txtid).IsLoggedIn() == true {
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Already Loggedin"))
				return
			}
		}

		log.Info().Str("instance", txtid).Str("qrcode", code).Msg("Get QR successful")
		response := map[string]interface{}{"QRCode": fmt.Sprintf("%s", code)}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Logs out device from Whatsapp (requires to scan QR next time)
func (s *server) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		jid := r.Context().Value("userinfo").(Values).Get("Jid")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		} else {
			if clientManager.GetWhatsmeowClient(txtid).IsLoggedIn() == true &&
				clientManager.GetWhatsmeowClient(txtid).IsConnected() == true {
				err := clientManager.GetWhatsmeowClient(txtid).Logout()
				if err != nil {
					log.Error().Str("jid", jid).Msg("Could not perform logout")
					s.Respond(w, r, http.StatusInternalServerError, errors.New("Could not perform logout"))
					return
				} else {
					log.Info().Str("jid", jid).Msg("Logged out")
					clientManager.DeleteWhatsmeowClient(txtid)
					killchannel[txtid] <- true
				}
			} else {
				if clientManager.GetWhatsmeowClient(txtid).IsConnected() == true {
					log.Warn().Str("jid", jid).Msg("Ignoring logout as it was not logged in")
					s.Respond(w, r, http.StatusInternalServerError, errors.New("Could not logout as it was not logged in"))
					return
				} else {
					log.Warn().Str("jid", jid).Msg("Ignoring logout as it was not connected")
					s.Respond(w, r, http.StatusInternalServerError, errors.New("Could not disconnect as it was not connected"))
					return
				}
			}
		}

		response := map[string]interface{}{"Details": "Logged out"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Pair by Phone. Retrieves the code to pair by phone number instead of QR
func (s *server) PairPhone() http.HandlerFunc {

	type pairStruct struct {
		Phone string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t pairStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		isLoggedIn := clientManager.GetWhatsmeowClient(txtid).IsLoggedIn()
		if isLoggedIn {
			log.Error().Msg(fmt.Sprintf("%s", "Already paired"))
			s.Respond(w, r, http.StatusBadRequest, errors.New("Already paired"))
			return
		}

		linkingCode, err := clientManager.GetWhatsmeowClient(txtid).PairPhone(t.Phone, true, whatsmeow.PairClientChrome, "Chrome (Linux)")
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		response := map[string]interface{}{"LinkingCode": linkingCode}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Gets Connected and LoggedIn Status
func (s *server) GetStatus() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		userInfo := r.Context().Value("userinfo").(Values)

		// Log all userinfo values
		log.Info().
			Str("Id", userInfo.Get("Id")).
			Str("Jid", userInfo.Get("Jid")).
			Str("Name", userInfo.Get("Name")).
			Str("Webhook", userInfo.Get("Webhook")).
			Str("Token", userInfo.Get("Token")).
			Str("Events", userInfo.Get("Events")).
			Str("Proxy", userInfo.Get("Proxy")).
			Msg("User info values")

		log.Info().Str("Name", userInfo.Get("Name")).Msg("User name")

		txtid := userInfo.Get("Id")

		/*
			if clientManager.GetWhatsmeowClient(txtid) == nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
				return
			}
		*/

		isConnected := clientManager.GetWhatsmeowClient(txtid).IsConnected()
		isLoggedIn := clientManager.GetWhatsmeowClient(txtid).IsLoggedIn()

		response := map[string]interface{}{
			"id":        txtid,
			"name":      userInfo.Get("Name"),
			"connected": isConnected,
			"loggedIn":  isLoggedIn,
			"token":     userInfo.Get("Token"),
			"jid":       userInfo.Get("Jid"),
			"webhook":   userInfo.Get("Webhook"),
			"events":    userInfo.Get("Events"),
			"proxy_url": userInfo.Get("Proxy"),
			"qrcode":    userInfo.Get("Qrcode"),
		}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends a document/attachment message
func (s *server) SendDocument() http.HandlerFunc {

	type documentStruct struct {
		Caption     string
		Phone       string
		Document    string
		FileName    string
		Id          string
		MimeType    string
		ContextInfo waE2E.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		msgid := ""
		var resp whatsmeow.SendResponse

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t documentStruct
		var err error
		err = decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Document == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Document in Payload"))
			return
		}

		if t.FileName == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing FileName in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var uploaded whatsmeow.UploadResponse
		var filedata []byte

		if t.Document[0:29] == "data:application/octet-stream" {
			var dataURL, err = dataurl.DecodeString(t.Document)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
				uploaded, err = clientManager.GetWhatsmeowClient(txtid).Upload(context.Background(), filedata, whatsmeow.MediaDocument)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to upload file: %v", err)))
					return
				}
			}
		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Document data should start with \"data:application/octet-stream;base64,\""))
			return
		}

		msg := &waE2E.Message{DocumentMessage: &waE2E.DocumentMessage{
			URL:        proto.String(uploaded.URL),
			FileName:   &t.FileName,
			DirectPath: proto.String(uploaded.DirectPath),
			MediaKey:   uploaded.MediaKey,
			Mimetype: proto.String(func() string {
				if t.MimeType != "" {
					return t.MimeType
				}
				return http.DetectContentType(filedata)
			}()),
			FileEncSHA256: uploaded.FileEncSHA256,
			FileSHA256:    uploaded.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(filedata))),
			Caption:       proto.String(t.Caption),
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends an audio message
func (s *server) SendAudio() http.HandlerFunc {

	type audioStruct struct {
		Phone       string
		Audio       string
		Caption     string
		Id          string
		ContextInfo waE2E.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		msgid := ""
		var resp whatsmeow.SendResponse

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t audioStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Audio == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Audio in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var uploaded whatsmeow.UploadResponse
		var filedata []byte

		if t.Audio[0:14] == "data:audio/ogg" {
			var dataURL, err = dataurl.DecodeString(t.Audio)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
				uploaded, err = clientManager.GetWhatsmeowClient(txtid).Upload(context.Background(), filedata, whatsmeow.MediaAudio)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to upload file: %v", err)))
					return
				}
			}
		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Audio data should start with \"data:audio/ogg;base64,\""))
			return
		}

		ptt := true
		mime := "audio/ogg; codecs=opus"

		msg := &waE2E.Message{AudioMessage: &waE2E.AudioMessage{
			URL:        proto.String(uploaded.URL),
			DirectPath: proto.String(uploaded.DirectPath),
			MediaKey:   uploaded.MediaKey,
			//Mimetype:      proto.String(http.DetectContentType(filedata)),
			Mimetype:      &mime,
			FileEncSHA256: uploaded.FileEncSHA256,
			FileSHA256:    uploaded.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(filedata))),
			PTT:           &ptt,
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends an Image message
func (s *server) SendImage() http.HandlerFunc {

	type imageStruct struct {
		Phone       string
		Image       string
		Caption     string
		Id          string
		MimeType    string
		ContextInfo waE2E.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		msgid := ""
		var resp whatsmeow.SendResponse

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t imageStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Image == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Image in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var uploaded whatsmeow.UploadResponse
		var filedata []byte
		var thumbnailBytes []byte

		if t.Image[0:10] == "data:image" {
			var dataURL, err = dataurl.DecodeString(t.Image)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
				uploaded, err = clientManager.GetWhatsmeowClient(txtid).Upload(context.Background(), filedata, whatsmeow.MediaImage)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to upload file: %v", err)))
					return
				}
			}

			// decode jpeg into image.Image
			reader := bytes.NewReader(filedata)
			img, _, err := image.Decode(reader)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not decode image for thumbnail preparation: %v", err)))
				return
			}

			// resize to width 72 using Lanczos resampling and preserve aspect ratio
			m := resize.Thumbnail(72, 72, img, resize.Lanczos3)

			tmpFile, err := os.CreateTemp("", "resized-*.jpg")
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not create temp file for thumbnail: %v", err)))
				return
			}
			defer tmpFile.Close()

			// write new image to file
			if err := jpeg.Encode(tmpFile, m, nil); err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to encode jpeg: %v", err)))
				return
			}

			thumbnailBytes, err = os.ReadFile(tmpFile.Name())
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to read %s: %v", tmpFile.Name(), err)))
				return
			}

		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Image data should start with \"data:image/png;base64,\""))
			return
		}

		msg := &waE2E.Message{ImageMessage: &waE2E.ImageMessage{
			Caption:    proto.String(t.Caption),
			URL:        proto.String(uploaded.URL),
			DirectPath: proto.String(uploaded.DirectPath),
			MediaKey:   uploaded.MediaKey,
			Mimetype: proto.String(func() string {
				if t.MimeType != "" {
					return t.MimeType
				}
				return http.DetectContentType(filedata)
			}()),
			FileEncSHA256: uploaded.FileEncSHA256,
			FileSHA256:    uploaded.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(filedata))),
			JPEGThumbnail: thumbnailBytes,
		}}

		if t.ContextInfo.StanzaID != nil {
			if msg.ImageMessage.ContextInfo == nil {
				msg.ImageMessage.ContextInfo = &waE2E.ContextInfo{
					StanzaID:      proto.String(*t.ContextInfo.StanzaID),
					Participant:   proto.String(*t.ContextInfo.Participant),
					QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
				}
			}
		}

		if t.ContextInfo.MentionedJID != nil {
			msg.ImageMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends Sticker message
func (s *server) SendSticker() http.HandlerFunc {

	type stickerStruct struct {
		Phone        string
		Sticker      string
		Id           string
		PngThumbnail []byte
		MimeType     string
		ContextInfo  waE2E.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		msgid := ""
		var resp whatsmeow.SendResponse

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t stickerStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Sticker == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Sticker in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var uploaded whatsmeow.UploadResponse
		var filedata []byte

		if t.Sticker[0:4] == "data" {
			var dataURL, err = dataurl.DecodeString(t.Sticker)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
				uploaded, err = clientManager.GetWhatsmeowClient(txtid).Upload(context.Background(), filedata, whatsmeow.MediaImage)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to upload file: %v", err)))
					return
				}
			}
		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Data should start with \"data:mime/type;base64,\""))
			return
		}

		msg := &waE2E.Message{StickerMessage: &waE2E.StickerMessage{
			URL:        proto.String(uploaded.URL),
			DirectPath: proto.String(uploaded.DirectPath),
			MediaKey:   uploaded.MediaKey,
			Mimetype: proto.String(func() string {
				if t.MimeType != "" {
					return t.MimeType
				}
				return http.DetectContentType(filedata)
			}()),
			FileEncSHA256: uploaded.FileEncSHA256,
			FileSHA256:    uploaded.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(filedata))),
			PngThumbnail:  t.PngThumbnail,
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends Video message
func (s *server) SendVideo() http.HandlerFunc {

	type imageStruct struct {
		Phone         string
		Video         string
		Caption       string
		Id            string
		JPEGThumbnail []byte
		MimeType      string
		ContextInfo   waE2E.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		msgid := ""
		var resp whatsmeow.SendResponse

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t imageStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Video == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Video in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var uploaded whatsmeow.UploadResponse
		var filedata []byte

		if t.Video[0:4] == "data" {
			var dataURL, err = dataurl.DecodeString(t.Video)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
				uploaded, err = clientManager.GetWhatsmeowClient(txtid).Upload(context.Background(), filedata, whatsmeow.MediaVideo)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to upload file: %v", err)))
					return
				}
			}
		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Data should start with \"data:mime/type;base64,\""))
			return
		}

		msg := &waE2E.Message{VideoMessage: &waE2E.VideoMessage{
			Caption:    proto.String(t.Caption),
			URL:        proto.String(uploaded.URL),
			DirectPath: proto.String(uploaded.DirectPath),
			MediaKey:   uploaded.MediaKey,
			Mimetype: proto.String(func() string {
				if t.MimeType != "" {
					return t.MimeType
				}
				return http.DetectContentType(filedata)
			}()),
			FileEncSHA256: uploaded.FileEncSHA256,
			FileSHA256:    uploaded.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(filedata))),
			JPEGThumbnail: t.JPEGThumbnail,
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends Contact
func (s *server) SendContact() http.HandlerFunc {

	type contactStruct struct {
		Phone       string
		Id          string
		Name        string
		Vcard       string
		ContextInfo waE2E.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t contactStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}
		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}
		if t.Name == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Name in Payload"))
			return
		}
		if t.Vcard == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Vcard in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		msg := &waE2E.Message{ContactMessage: &waE2E.ContactMessage{
			DisplayName: &t.Name,
			Vcard:       &t.Vcard,
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends location
func (s *server) SendLocation() http.HandlerFunc {

	type locationStruct struct {
		Phone       string
		Id          string
		Name        string
		Latitude    float64
		Longitude   float64
		ContextInfo waE2E.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t locationStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}
		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}
		if t.Latitude == 0 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Latitude in Payload"))
			return
		}
		if t.Longitude == 0 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Longitude in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		msg := &waE2E.Message{LocationMessage: &waE2E.LocationMessage{
			DegreesLatitude:  &t.Latitude,
			DegreesLongitude: &t.Longitude,
			Name:             &t.Name,
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends Buttons (not implemented, does not work)

func (s *server) SendButtons() http.HandlerFunc {

	type buttonStruct struct {
		ButtonId   string
		ButtonText string
	}
	type textStruct struct {
		Phone   string
		Title   string
		Buttons []buttonStruct
		Id      string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t textStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Title == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Title in Payload"))
			return
		}

		if len(t.Buttons) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Buttons in Payload"))
			return
		}
		if len(t.Buttons) > 3 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("buttons cant more than 3"))
			return
		}

		recipient, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var buttons []*waE2E.ButtonsMessage_Button

		for _, item := range t.Buttons {
			buttons = append(buttons, &waE2E.ButtonsMessage_Button{
				ButtonID:       proto.String(item.ButtonId),
				ButtonText:     &waE2E.ButtonsMessage_Button_ButtonText{DisplayText: proto.String(item.ButtonText)},
				Type:           waE2E.ButtonsMessage_Button_RESPONSE.Enum(),
				NativeFlowInfo: &waE2E.ButtonsMessage_Button_NativeFlowInfo{},
			})
		}

		msg2 := &waE2E.ButtonsMessage{
			ContentText: proto.String(t.Title),
			HeaderType:  waE2E.ButtonsMessage_EMPTY.Enum(),
			Buttons:     buttons,
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, &waE2E.Message{ViewOnceMessage: &waE2E.FutureProofMessage{
			Message: &waE2E.Message{
				ButtonsMessage: msg2,
			},
		}}, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// SendList
// https://github.com/tulir/whatsmeow/issues/305
func (s *server) SendList() http.HandlerFunc {

	type rowsStruct struct {
		RowId       string
		Title       string
		Description string
	}

	type sectionsStruct struct {
		Title string
		Rows  []rowsStruct
	}

	type listStruct struct {
		Phone       string
		Title       string
		Description string
		ButtonText  string
		FooterText  string
		Sections    []sectionsStruct
		Id          string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t listStruct
		err := decoder.Decode(&t)
		marshal, _ := json.Marshal(t)
		fmt.Println(string(marshal))
		if err != nil {
			fmt.Println(err)
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Phone in Payload"))
			return
		}

		if t.Title == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Title in Payload"))
			return
		}

		if t.Description == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Description in Payload"))
			return
		}

		if t.ButtonText == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing ButtonText in Payload"))
			return
		}

		if len(t.Sections) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Sections in Payload"))
			return
		}
		recipient, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Phone"))
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var sections []*waE2E.ListMessage_Section

		for _, item := range t.Sections {
			var rows []*waE2E.ListMessage_Row
			id := 1
			for _, row := range item.Rows {
				var idtext string
				if row.RowId == "" {
					idtext = strconv.Itoa(id)
				} else {
					idtext = row.RowId
				}
				rows = append(rows, &waE2E.ListMessage_Row{
					RowID:       proto.String(idtext),
					Title:       proto.String(row.Title),
					Description: proto.String(row.Description),
				})
			}

			sections = append(sections, &waE2E.ListMessage_Section{
				Title: proto.String(item.Title),
				Rows:  rows,
			})
		}
		msg1 := &waE2E.ListMessage{
			Title:       proto.String(t.Title),
			Description: proto.String(t.Description),
			ButtonText:  proto.String(t.ButtonText),
			ListType:    waE2E.ListMessage_SINGLE_SELECT.Enum(),
			Sections:    sections,
			FooterText:  proto.String(t.FooterText),
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, &waE2E.Message{
			ViewOnceMessage: &waE2E.FutureProofMessage{
				Message: &waE2E.Message{
					ListMessage: msg1,
				},
			}}, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends a regular text message
func (s *server) SendMessage() http.HandlerFunc {

	type textStruct struct {
		Phone       string
		Body        string
		Id          string
		ContextInfo waE2E.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t textStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Body == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Body in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = clientManager.GetWhatsmeowClient(txtid).GenerateMessageID()
		} else {
			msgid = t.Id
		}

		msg := &waE2E.Message{
			ExtendedTextMessage: &waE2E.ExtendedTextMessage{
				Text: &t.Body,
			},
		}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

func (s *server) SendPoll() http.HandlerFunc {
	type pollRequest struct {
		Group   string   `json:"group"`   // The recipient's group id (120363313346913103@g.us)
		Header  string   `json:"header"`  // The poll's headline text
		Options []string `json:"options"` // The list of poll options
		Id      string
	}

	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var req pollRequest
		err := decoder.Decode(&req)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		if req.Group == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Grouop in payload"))
			return
		}

		if req.Header == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Header in payload"))
			return
		}

		if len(req.Options) < 2 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("At least 2 options are required"))
			return
		}

		if req.Id == "" {
			msgid = clientManager.GetWhatsmeowClient(txtid).GenerateMessageID()
		} else {
			msgid = req.Id
		}

		recipient, err := validateMessageFields(req.Group, nil, nil)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		pollMessage := clientManager.GetWhatsmeowClient(txtid).BuildPollCreation(req.Header, req.Options, 1)
		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, pollMessage, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to send poll: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Poll sent")

		response := map[string]interface{}{"Details": "Poll sent successfully", "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// Delete message
func (s *server) DeleteMessage() http.HandlerFunc {

	type textStruct struct {
		Phone string
		Id    string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t textStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Id == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Id in Payload"))
			return
		}

		msgid = t.Id

		recipient, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
			return
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, clientManager.GetWhatsmeowClient(txtid).BuildRevoke(recipient, types.EmptyJID, msgid))
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message deleted")
		response := map[string]interface{}{"Details": "Deleted", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Sends a edit text message
func (s *server) SendEditMessage() http.HandlerFunc {

	type editStruct struct {
		Phone       string
		Body        string
		Id          string
		ContextInfo waE2E.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t editStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Body == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Body in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Id in Payload"))
			return
		} else {
			msgid = t.Id
		}

		msg := &waE2E.Message{
			ExtendedTextMessage: &waE2E.ExtendedTextMessage{
				Text: &t.Body,
			},
		}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waE2E.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, clientManager.GetWhatsmeowClient(txtid).BuildEdit(recipient, msgid, msg))
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending edit message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message edit sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

/*
// Sends a Template message
func (s *server) SendTemplate() http.HandlerFunc {

	type buttonStruct struct {
		DisplayText string
		Id          string
		Url         string
		PhoneNumber string
		Type        string
	}

	type templateStruct struct {
		Phone   string
		Content string
		Footer  string
		Id      string
		Buttons []buttonStruct
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientManager.GetWhatsmeowClient(userid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse
//var ts time.Time

		decoder := json.NewDecoder(r.Body)
		var t templateStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Content == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Content in Payload"))
			return
		}

		if t.Footer == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Footer in Payload"))
			return
		}

		if len(t.Buttons) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Buttons in Payload"))
			return
		}

		recipient, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var buttons []*waE2E.HydratedTemplateButton

		id := 1
		for _, item := range t.Buttons {
			switch item.Type {
			case "quickreply":
				var idtext string
				text := item.DisplayText
				if item.Id == "" {
					idtext = strconv.Itoa(id)
				} else {
					idtext = item.Id
				}
				buttons = append(buttons, &waE2E.HydratedTemplateButton{
					HydratedButton: &waE2E.HydratedTemplateButton_QuickReplyButton{
						QuickReplyButton: &waE2E.HydratedQuickReplyButton{
							DisplayText: &text,
							Id:          proto.String(idtext),
						},
					},
				})
			case "url":
				text := item.DisplayText
				url := item.Url
				buttons = append(buttons, &waE2E.HydratedTemplateButton{
					HydratedButton: &waE2E.HydratedTemplateButton_UrlButton{
						UrlButton: &waE2E.HydratedURLButton{
							DisplayText: &text,
							Url:         &url,
						},
					},
				})
			case "call":
				text := item.DisplayText
				phonenumber := item.PhoneNumber
				buttons = append(buttons, &waE2E.HydratedTemplateButton{
					HydratedButton: &waE2E.HydratedTemplateButton_CallButton{
						CallButton: &waE2E.HydratedCallButton{
							DisplayText: &text,
							PhoneNumber: &phonenumber,
						},
					},
				})
			default:
				text := item.DisplayText
				buttons = append(buttons, &waE2E.HydratedTemplateButton{
					HydratedButton: &waE2E.HydratedTemplateButton_QuickReplyButton{
						QuickReplyButton: &waE2E.HydratedQuickReplyButton{
							DisplayText: &text,
							Id:          proto.String(string(id)),
						},
					},
				})
			}
			id++
		}

		msg := &waE2E.Message{TemplateMessage: &waE2E.TemplateMessage{
			HydratedTemplate: &waE2E.HydratedFourRowTemplate{
				HydratedContentText: proto.String(t.Content),
				HydratedFooterText:  proto.String(t.Footer),
				HydratedButtons:     buttons,
				TemplateId:          proto.String("1"),
			},
		},
		}

		resp, err = clientManager.GetWhatsmeowClient(userid).SendMessage(context.Background(),recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}
*/
// checks if users/phones are on Whatsapp
func (s *server) CheckUser() http.HandlerFunc {

	type checkUserStruct struct {
		Phone []string
	}

	type User struct {
		Query        string
		IsInWhatsapp bool
		JID          string
		VerifiedName string
	}

	type UserCollection struct {
		Users []User
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t checkUserStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if len(t.Phone) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		resp, err := clientManager.GetWhatsmeowClient(txtid).IsOnWhatsApp(t.Phone)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to check if users are on WhatsApp: %s", err)))
			return
		}

		uc := new(UserCollection)
		for _, item := range resp {
			if item.VerifiedName != nil {
				var msg = User{Query: item.Query, IsInWhatsapp: item.IsIn, JID: fmt.Sprintf("%s", item.JID), VerifiedName: item.VerifiedName.Details.GetVerifiedName()}
				uc.Users = append(uc.Users, msg)
			} else {
				var msg = User{Query: item.Query, IsInWhatsapp: item.IsIn, JID: fmt.Sprintf("%s", item.JID), VerifiedName: ""}
				uc.Users = append(uc.Users, msg)
			}
		}
		responseJson, err := json.Marshal(uc)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Gets user information
func (s *server) GetUser() http.HandlerFunc {

	type checkUserStruct struct {
		Phone []string
	}

	type UserCollection struct {
		Users map[types.JID]types.UserInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t checkUserStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if len(t.Phone) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		var jids []types.JID
		for _, arg := range t.Phone {
			jid, err := types.ParseJID(arg)
			if err != nil {
				return
			}
			jids = append(jids, jid)
		}
		resp, err := clientManager.GetWhatsmeowClient(txtid).GetUserInfo(jids)

		if err != nil {
			msg := fmt.Sprintf("Failed to get user info: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		uc := new(UserCollection)
		uc.Users = make(map[types.JID]types.UserInfo)

		for jid, info := range resp {
			uc.Users[jid] = info
		}

		responseJson, err := json.Marshal(uc)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

func (s *server) SendPresence() http.HandlerFunc {

	type PresenceRequest struct {
		Type string `json:"type" form:"type"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var pre PresenceRequest
		err := decoder.Decode(&pre)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		var presence types.Presence

		switch pre.Type {
		case "available":
			presence = types.PresenceAvailable
		case "unavailable":
			presence = types.PresenceUnavailable
		default:
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid presence type. Allowed values: 'available', 'unavailable'"))
			return
		}

		log.Info().Str("presence", pre.Type).Msg("Your global presence status")

		err = clientManager.GetWhatsmeowClient(txtid).SendPresence(presence)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failure sending presence to Whatsapp servers"))
			return
		}

		response := map[string]interface{}{"Details": "Presence set successfuly"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return

	}
}

// Gets avatar info for user
func (s *server) GetAvatar() http.HandlerFunc {

	type getAvatarStruct struct {
		Phone   string
		Preview bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t getAvatarStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if len(t.Phone) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		jid, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
			return
		}

		var pic *types.ProfilePictureInfo

		existingID := ""
		pic, err = clientManager.GetWhatsmeowClient(txtid).GetProfilePictureInfo(jid, &whatsmeow.GetProfilePictureParams{
			Preview:    t.Preview,
			ExistingID: existingID,
		})
		if err != nil {
			msg := fmt.Sprintf("Failed to get avatar: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
			return
		}

		if pic == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No avatar found"))
			return
		}

		log.Info().Str("id", pic.ID).Str("url", pic.URL).Msg("Got avatar")

		responseJson, err := json.Marshal(pic)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Gets all contacts
func (s *server) GetContacts() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		result := map[types.JID]types.ContactInfo{}
		result, err := clientManager.GetWhatsmeowClient(txtid).Store.Contacts.GetAllContacts()
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		responseJson, err := json.Marshal(result)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Sets Chat Presence (typing/paused/recording audio)
func (s *server) ChatPresence() http.HandlerFunc {

	type chatPresenceStruct struct {
		Phone string
		State string
		Media types.ChatPresenceMedia
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t chatPresenceStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if len(t.Phone) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if len(t.State) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing State in Payload"))
			return
		}

		jid, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
			return
		}

		err = clientManager.GetWhatsmeowClient(txtid).SendChatPresence(jid, types.ChatPresence(t.State), types.ChatPresenceMedia(t.Media))
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failure sending chat presence to Whatsapp servers"))
			return
		}

		response := map[string]interface{}{"Details": "Chat presence set successfuly"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Downloads Image and returns base64 representation
func (s *server) DownloadImage() http.HandlerFunc {

	type downloadImageStruct struct {
		Url           string
		DirectPath    string
		MediaKey      []byte
		Mimetype      string
		FileEncSHA256 []byte
		FileSHA256    []byte
		FileLength    uint64
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		mimetype := ""
		var imgdata []byte

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// check/creates user directory for files
		userDirectory := filepath.Join(s.exPath, "files", "user_"+txtid)
		_, err := os.Stat(userDirectory)
		if os.IsNotExist(err) {
			errDir := os.MkdirAll(userDirectory, 0751)
			if errDir != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not create user directory (%s)", userDirectory)))
				return
			}
		}

		decoder := json.NewDecoder(r.Body)
		var t downloadImageStruct
		err = decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		msg := &waE2E.Message{ImageMessage: &waE2E.ImageMessage{
			URL:           proto.String(t.Url),
			DirectPath:    proto.String(t.DirectPath),
			MediaKey:      t.MediaKey,
			Mimetype:      proto.String(t.Mimetype),
			FileEncSHA256: t.FileEncSHA256,
			FileSHA256:    t.FileSHA256,
			FileLength:    &t.FileLength,
		}}

		img := msg.GetImageMessage()

		if img != nil {
			imgdata, err = clientManager.GetWhatsmeowClient(txtid).Download(img)
			if err != nil {
				log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to download image")
				msg := fmt.Sprintf("Failed to download image %v", err)
				s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
				return
			}
			mimetype = img.GetMimetype()
		}

		dataURL := dataurl.New(imgdata, mimetype)
		response := map[string]interface{}{"Mimetype": mimetype, "Data": dataURL.String()}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Downloads Document and returns base64 representation
func (s *server) DownloadDocument() http.HandlerFunc {

	type downloadDocumentStruct struct {
		Url           string
		DirectPath    string
		MediaKey      []byte
		Mimetype      string
		FileEncSHA256 []byte
		FileSHA256    []byte
		FileLength    uint64
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		mimetype := ""
		var docdata []byte

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// check/creates user directory for files
		userDirectory := filepath.Join(s.exPath, "files", "user_"+txtid)
		_, err := os.Stat(userDirectory)
		if os.IsNotExist(err) {
			errDir := os.MkdirAll(userDirectory, 0751)
			if errDir != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not create user directory (%s)", userDirectory)))
				return
			}
		}

		decoder := json.NewDecoder(r.Body)
		var t downloadDocumentStruct
		err = decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		msg := &waE2E.Message{DocumentMessage: &waE2E.DocumentMessage{
			URL:           proto.String(t.Url),
			DirectPath:    proto.String(t.DirectPath),
			MediaKey:      t.MediaKey,
			Mimetype:      proto.String(t.Mimetype),
			FileEncSHA256: t.FileEncSHA256,
			FileSHA256:    t.FileSHA256,
			FileLength:    &t.FileLength,
		}}

		doc := msg.GetDocumentMessage()

		if doc != nil {
			docdata, err = clientManager.GetWhatsmeowClient(txtid).Download(doc)
			if err != nil {
				log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to download document")
				msg := fmt.Sprintf("Failed to download document %v", err)
				s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
				return
			}
			mimetype = doc.GetMimetype()
		}

		dataURL := dataurl.New(docdata, mimetype)
		response := map[string]interface{}{"Mimetype": mimetype, "Data": dataURL.String()}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Downloads Video and returns base64 representation
func (s *server) DownloadVideo() http.HandlerFunc {

	type downloadVideoStruct struct {
		Url           string
		DirectPath    string
		MediaKey      []byte
		Mimetype      string
		FileEncSHA256 []byte
		FileSHA256    []byte
		FileLength    uint64
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		mimetype := ""
		var docdata []byte

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// check/creates user directory for files
		userDirectory := filepath.Join(s.exPath, "files", "user_"+txtid)
		_, err := os.Stat(userDirectory)
		if os.IsNotExist(err) {
			errDir := os.MkdirAll(userDirectory, 0751)
			if errDir != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not create user directory (%s)", userDirectory)))
				return
			}
		}

		decoder := json.NewDecoder(r.Body)
		var t downloadVideoStruct
		err = decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		msg := &waE2E.Message{VideoMessage: &waE2E.VideoMessage{
			URL:           proto.String(t.Url),
			DirectPath:    proto.String(t.DirectPath),
			MediaKey:      t.MediaKey,
			Mimetype:      proto.String(t.Mimetype),
			FileEncSHA256: t.FileEncSHA256,
			FileSHA256:    t.FileSHA256,
			FileLength:    &t.FileLength,
		}}

		doc := msg.GetVideoMessage()

		if doc != nil {
			docdata, err = clientManager.GetWhatsmeowClient(txtid).Download(doc)
			if err != nil {
				log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to download video")
				msg := fmt.Sprintf("Failed to download video %v", err)
				s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
				return
			}
			mimetype = doc.GetMimetype()
		}

		dataURL := dataurl.New(docdata, mimetype)
		response := map[string]interface{}{"Mimetype": mimetype, "Data": dataURL.String()}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Downloads Audio and returns base64 representation
func (s *server) DownloadAudio() http.HandlerFunc {

	type downloadAudioStruct struct {
		Url           string
		DirectPath    string
		MediaKey      []byte
		Mimetype      string
		FileEncSHA256 []byte
		FileSHA256    []byte
		FileLength    uint64
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		mimetype := ""
		var docdata []byte

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// check/creates user directory for files
		userDirectory := filepath.Join(s.exPath, "files", "user_"+txtid)
		_, err := os.Stat(userDirectory)
		if os.IsNotExist(err) {
			errDir := os.MkdirAll(userDirectory, 0751)
			if errDir != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not create user directory (%s)", userDirectory)))
				return
			}
		}

		decoder := json.NewDecoder(r.Body)
		var t downloadAudioStruct
		err = decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		msg := &waE2E.Message{AudioMessage: &waE2E.AudioMessage{
			URL:           proto.String(t.Url),
			DirectPath:    proto.String(t.DirectPath),
			MediaKey:      t.MediaKey,
			Mimetype:      proto.String(t.Mimetype),
			FileEncSHA256: t.FileEncSHA256,
			FileSHA256:    t.FileSHA256,
			FileLength:    &t.FileLength,
		}}

		doc := msg.GetAudioMessage()

		if doc != nil {
			docdata, err = clientManager.GetWhatsmeowClient(txtid).Download(doc)
			if err != nil {
				log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to download audio")
				msg := fmt.Sprintf("Failed to download audio %v", err)
				s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
				return
			}
			mimetype = doc.GetMimetype()
		}

		dataURL := dataurl.New(docdata, mimetype)
		response := map[string]interface{}{"Mimetype": mimetype, "Data": dataURL.String()}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// React
func (s *server) React() http.HandlerFunc {

	type textStruct struct {
		Phone string
		Body  string
		Id    string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t textStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Body == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Body in Payload"))
			return
		}

		recipient, ok := parseJID(t.Phone)
		if !ok {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		if t.Id == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Id in Payload"))
			return
		} else {
			msgid = t.Id
		}

		fromMe := false
		if strings.HasPrefix(msgid, "me:") {
			fromMe = true
			msgid = msgid[len("me:"):]
		}
		reaction := t.Body
		if reaction == "remove" {
			reaction = ""
		}

		msg := &waE2E.Message{
			ReactionMessage: &waE2E.ReactionMessage{
				Key: &waCommon.MessageKey{
					RemoteJID: proto.String(recipient.String()),
					FromMe:    proto.Bool(fromMe),
					ID:        proto.String(msgid),
				},
				Text:              proto.String(reaction),
				GroupingKey:       proto.String(reaction),
				SenderTimestampMS: proto.Int64(time.Now().UnixMilli()),
			},
		}

		resp, err = clientManager.GetWhatsmeowClient(txtid).SendMessage(context.Background(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Mark messages as read
func (s *server) MarkRead() http.HandlerFunc {

	type markReadStruct struct {
		Id     []string
		Chat   types.JID
		Sender types.JID
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t markReadStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Chat.String() == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Chat in Payload"))
			return
		}

		if len(t.Id) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Id in Payload"))
			return
		}

		err = clientManager.GetWhatsmeowClient(txtid).MarkRead(t.Id, time.Now(), t.Chat, t.Sender)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failure marking messages as read"))
			return
		}

		response := map[string]interface{}{"Details": "Message(s) marked as read"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// List groups
func (s *server) ListGroups() http.HandlerFunc {

	type GroupCollection struct {
		Groups []types.GroupInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		resp, err := clientManager.GetWhatsmeowClient(txtid).GetJoinedGroups()

		if err != nil {
			msg := fmt.Sprintf("Failed to get group list: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		gc := new(GroupCollection)
		for _, info := range resp {
			gc.Groups = append(gc.Groups, *info)
		}

		responseJson, err := json.Marshal(gc)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Get group info
func (s *server) GetGroupInfo() http.HandlerFunc {

	type getGroupInfoStruct struct {
		GroupJID string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// Get GroupJID from query parameter
		groupJID := r.URL.Query().Get("groupJID")
		if groupJID == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing groupJID parameter"))
			return
		}

		group, ok := parseJID(groupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		resp, err := clientManager.GetWhatsmeowClient(txtid).GetGroupInfo(group)

		if err != nil {
			msg := fmt.Sprintf("Failed to get group info: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		responseJson, err := json.Marshal(resp)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Get group invite link
func (s *server) GetGroupInviteLink() http.HandlerFunc {

	type getGroupInfoStruct struct {
		GroupJID string
		Reset    bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// Get GroupJID from query parameter
		groupJID := r.URL.Query().Get("groupJID")
		if groupJID == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing groupJID parameter"))
			return
		}

		// Get reset parameter
		resetParam := r.URL.Query().Get("reset")
		reset := false
		if resetParam != "" {
			var err error
			reset, err = strconv.ParseBool(resetParam)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid reset parameter, must be true or false"))
				return
			}
		}

		group, ok := parseJID(groupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		resp, err := clientManager.GetWhatsmeowClient(txtid).GetGroupInviteLink(group, reset)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to get group invite link")
			msg := fmt.Sprintf("Failed to get group invite link: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"InviteLink": resp}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Join group invite link
func (s *server) GroupJoin() http.HandlerFunc {

	type joinGroupStruct struct {
		Code string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t joinGroupStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Code == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Code in Payload"))
			return
		}

		_, err = clientManager.GetWhatsmeowClient(txtid).JoinGroupWithLink(t.Code)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to join group")
			msg := fmt.Sprintf("Failed to join group: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group joined successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// add, remove, promote and demote members group
func (s *server) UpdateGroupParticipants() http.HandlerFunc {

	type updateGroupParticipantsStruct struct {
		GroupJID string
		Phone    []string
		// Action string // add, remove, promote, demote
		Action string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t updateGroupParticipantsStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		if len(t.Phone) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}
		// parse phone numbers
		phoneParsed := make([]types.JID, len(t.Phone))
		for i, phone := range t.Phone {
			phoneParsed[i], ok = parseJID(phone)
			if !ok {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
				return
			}
		}

		if t.Action == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Action in Payload"))
			return
		}

		// parse action

		var action whatsmeow.ParticipantChange
		switch t.Action {
		case "add":
			action = "add"
		case "remove":
			action = "remove"
		case "promote":
			action = "promote"
		case "demote":
			action = "demote"
		default:
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid Action in Payload"))
			return
		}

		_, err = clientManager.GetWhatsmeowClient(txtid).UpdateGroupParticipants(group, phoneParsed, action)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to change participant group")
			msg := fmt.Sprintf("Failed to change participant group: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Participants updated successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Get group invite info
func (s *server) GetGroupInviteInfo() http.HandlerFunc {

	type getGroupInviteInfoStruct struct {
		Code string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t getGroupInviteInfoStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Code == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Code in Payload"))
			return
		}

		groupInfo, err := clientManager.GetWhatsmeowClient(txtid).GetGroupInfoFromLink(t.Code)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to get group invite info")
			msg := fmt.Sprintf("Failed to get group invite info: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		responseJson, err := json.Marshal(groupInfo)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Set group photo
func (s *server) SetGroupPhoto() http.HandlerFunc {

	type setGroupPhotoStruct struct {
		GroupJID string
		Image    string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t setGroupPhotoStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		if t.Image == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Image in Payload"))
			return
		}

		var filedata []byte

		if t.Image[0:13] == "data:image/jp" {
			var dataURL, err = dataurl.DecodeString(t.Image)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
			}
		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Image data should start with \"data:image/jpeg;base64,\""))
			return
		}

		picture_id, err := clientManager.GetWhatsmeowClient(txtid).SetGroupPhoto(group, filedata)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to set group photo")
			msg := fmt.Sprintf("Failed to set group photo: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Photo set successfully", "PictureID": picture_id}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Set group name
func (s *server) SetGroupName() http.HandlerFunc {

	type setGroupNameStruct struct {
		GroupJID string
		Name     string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t setGroupNameStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		if t.Name == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Name in Payload"))
			return
		}

		err = clientManager.GetWhatsmeowClient(txtid).SetGroupName(group, t.Name)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to set group name")
			msg := fmt.Sprintf("Failed to set group name: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Name set successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Set group topic (description)
func (s *server) SetGroupTopic() http.HandlerFunc {

	type setGroupTopicStruct struct {
		GroupJID string
		Topic    string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t setGroupTopicStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		if t.Topic == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Topic in Payload"))
			return
		}

		err = clientManager.GetWhatsmeowClient(txtid).SetGroupTopic(group, "", "", t.Topic)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to set group topic")
			msg := fmt.Sprintf("Failed to set group topic: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Topic set successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

func (s *server) GroupLeave() http.HandlerFunc {

	type groupLeaveStruct struct {
		GroupJID string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t groupLeaveStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		err = clientManager.GetWhatsmeowClient(txtid).LeaveGroup(group)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to leave group")
			msg := fmt.Sprintf("Failed to leave group: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group left successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// SetGroupAnnounce post
func (s *server) SetGroupAnnounce() http.HandlerFunc {

	type setGroupAnnounceStruct struct {
		GroupJID string
		Announce bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t setGroupAnnounceStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		err = clientManager.GetWhatsmeowClient(txtid).SetGroupAnnounce(group, t.Announce)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to set group announce")
			msg := fmt.Sprintf("Failed to set group announce: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Announce set successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// List newsletters
func (s *server) ListNewsletter() http.HandlerFunc {

	type NewsletterCollection struct {
		Newsletter []types.NewsletterMetadata
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if clientManager.GetWhatsmeowClient(txtid) == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		resp, err := clientManager.GetWhatsmeowClient(txtid).GetSubscribedNewsletters()

		if err != nil {
			msg := fmt.Sprintf("Failed to get newsletter list: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		gc := new(NewsletterCollection)
		gc.Newsletter = []types.NewsletterMetadata{}
		for _, info := range resp {
			gc.Newsletter = append(gc.Newsletter, *info)
		}

		responseJson, err := json.Marshal(gc)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Admin List users
func (s *server) ListUsers() http.HandlerFunc {
	type usersStruct struct {
		Id         string         `db:"id"`
		Name       string         `db:"name"`
		Token      string         `db:"token"`
		Webhook    string         `db:"webhook"`
		Jid        string         `db:"jid"`
		Qrcode     string         `db:"qrcode"`
		Connected  sql.NullBool   `db:"connected"`
		Expiration sql.NullInt64  `db:"expiration"`
		ProxyURL   sql.NullString `db:"proxy_url"`
		Events     string         `db:"events"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		userID, hasID := vars["id"]

		var query string
		var args []interface{}

		/*
			// Query the database to get the list of users
			rows, err := s.db.Queryx("SELECT id, name, token, webhook, jid, qrcode, connected, expiration, events FROM users")
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Problem accessing DB"))
				return
			}
			defer rows.Close()
		*/

		if hasID {
			// Fetch a single user
			query = "SELECT id, name, token, webhook, jid, qrcode, connected, expiration, proxy_url, events FROM users WHERE id = $1"
			args = append(args, userID)
		} else {
			// Fetch all users
			query = "SELECT id, name, token, webhook, jid, qrcode, connected, expiration, proxy_url, events FROM users"
		}

		rows, err := s.db.Queryx(query, args...)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Problem accessing DB"))
			return
		}
		defer rows.Close()

		// Create a slice to store the user data
		users := []map[string]interface{}{}
		// Iterate over the rows and populate the user data
		for rows.Next() {
			var user usersStruct
			err := rows.StructScan(&user)
			if err != nil {
				log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Admin DB Error")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Problem accessing DB"))
				return
			}

			isConnected := false
			isLoggedIn := false
			if clientManager.GetWhatsmeowClient(user.Id) != nil {
				isConnected = clientManager.GetWhatsmeowClient(user.Id).IsConnected()
				isLoggedIn = clientManager.GetWhatsmeowClient(user.Id).IsLoggedIn()
			}

			//"connected":  user.Connected.Bool,
			userMap := map[string]interface{}{
				"id":         user.Id,
				"name":       user.Name,
				"token":      user.Token,
				"webhook":    user.Webhook,
				"jid":        user.Jid,
				"qrcode":     user.Qrcode,
				"connected":  isConnected,
				"loggedIn":   isLoggedIn,
				"expiration": user.Expiration.Int64,
				"proxy_url":  user.ProxyURL.String,
				"events":     user.Events,
			}
			users = append(users, userMap)
		}
		// Check for any error that occurred during iteration
		if err := rows.Err(); err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Problem accessing DB"))
			return
		}

		// Encode users slice into a JSON string
		responseJson, err := json.Marshal(users)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		s.Respond(w, r, http.StatusOK, string(responseJson))

	}
}

func (s *server) AddUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Parse the request body
		var user struct {
			Name       string `json:"name"`
			Token      string `json:"token"`
			Webhook    string `json:"webhook,omitempty"`
			Expiration int    `json:"expiration,omitempty"`
			Events     string `json:"events,omitempty"`
			ProxyURL   string `json:"proxy_url,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			s.respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code":    http.StatusBadRequest,
				"error":   "Invalid request payload",
				"success": false,
			})
			return
		}

		// Validate required fields
		if user.Token == "" {
			s.respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code":    http.StatusBadRequest,
				"error":   "Token is required",
				"success": false,
			})
			return
		}

		if user.Name == "" {
			s.respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code":    http.StatusBadRequest,
				"error":   "Missing required fields",
				"success": false,
				"details": "Required fields: name, token",
			})
			return
		}

		// Set defaults
		if user.Events == "" {
			user.Events = "All"
		}
		if user.ProxyURL == "" {
			user.ProxyURL = ""
		}
		if user.Webhook == "" {
			user.Webhook = ""
		}

		// Check for existing user
		var count int
		if err := s.db.Get(&count, "SELECT COUNT(*) FROM users WHERE token = $1", user.Token); err != nil {
			s.respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"code":    http.StatusInternalServerError,
				"error":   "Database error",
				"success": false,
			})
			return
		}
		if count > 0 {
			s.respondWithJSON(w, http.StatusConflict, map[string]interface{}{
				"code":    http.StatusConflict,
				"error":   "User with this token already exists",
				"success": false,
			})
			return
		}

		// Validate events
		eventList := strings.Split(user.Events, ",")
		for _, event := range eventList {
			event = strings.TrimSpace(event)
			if !Find(messageTypes, event) {
				s.respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
					"code":    http.StatusBadRequest,
					"error":   "Invalid event type",
					"success": false,
					"details": "Invalid event: " + event,
				})
				return
			}
		}

		// Generate ID
		id, err := GenerateRandomID()
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate random ID")
			s.respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"code":    http.StatusInternalServerError,
				"error":   "Failed to generate user ID",
				"success": false,
			})
			return
		}

		// Insert user
		if _, err = s.db.Exec(
			"INSERT INTO users (id, name, token, webhook, expiration, events, jid, qrcode, proxy_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
			id, user.Name, user.Token, user.Webhook, user.Expiration, user.Events, "", "", user.ProxyURL,
		); err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Admin DB Error")
			s.respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"code":    http.StatusInternalServerError,
				"error":   "Database error",
				"success": false,
			})
			return
		}

		// Success response
		s.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
			"code": http.StatusCreated,
			"data": map[string]interface{}{
				"id":   id,
				"name": user.Name,
			},
			"success": true,
		})
	}
}

func (s *server) DeleteUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Get the user ID from the request URL
		vars := mux.Vars(r)
		userID := vars["id"]

		// Delete the user from the database
		result, err := s.db.Exec("DELETE FROM users WHERE id=$1", userID)
		if err != nil {
			s.respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"code":    http.StatusInternalServerError,
				"error":   "Database error",
				"success": false,
			})
			return
		}

		// Check if the user was deleted
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			s.respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"code":    http.StatusInternalServerError,
				"error":   "Failed to verify deletion",
				"success": false,
			})
			return
		}
		if rowsAffected == 0 {
			s.respondWithJSON(w, http.StatusNotFound, map[string]interface{}{
				"code":    http.StatusNotFound,
				"error":   "User not found",
				"success": false,
				"details": fmt.Sprintf("No user found with ID: %s", userID),
			})
			return
		}
		s.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"code":    http.StatusOK,
			"data":    map[string]string{"id": userID},
			"success": true,
			"details": "User deleted successfully",
		})
	}
}

func (s *server) DeleteUserComplete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		vars := mux.Vars(r)
		id := vars["id"]

		// Validate ID
		if id == "" {
			s.respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code":    http.StatusBadRequest,
				"error":   "Missing ID",
				"success": false,
			})
			return
		}

		// Check if user exists
		var exists bool
		err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", id).Scan(&exists)
		if err != nil {
			s.respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"code":    http.StatusInternalServerError,
				"error":   "Database error",
				"success": false,
				"details": "Problem checking user existence",
			})
			return
		}
		if !exists {
			s.respondWithJSON(w, http.StatusNotFound, map[string]interface{}{
				"code":    http.StatusNotFound,
				"error":   "User not found",
				"success": false,
				"details": fmt.Sprintf("No user found with ID: %s", id),
			})
			return
		}

		// Get user info before deletion
		var uname, jid, token string
		err = s.db.QueryRow("SELECT name, jid, token FROM users WHERE id = $1", id).Scan(&uname, &jid, &token)
		if err != nil {
			log.Error().Err(err).Str("id", id).Msg("Problem retrieving user information")
			// Continue anyway since we have the ID
		}

		// 1. Logout and disconnect instance
		if client := clientManager.GetWhatsmeowClient(id); client != nil {
			if client.IsConnected() {
				log.Info().Str("id", id).Msg("Logging out user")
				client.Logout()
			}
			log.Info().Str("id", id).Msg("Disconnecting from WhatsApp")
			client.Disconnect()
		}

		// 2. Remove from DB
		_, err = s.db.Exec("DELETE FROM users WHERE id = $1", id)
		if err != nil {
			s.respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"code":    http.StatusInternalServerError,
				"error":   "Database error",
				"success": false,
				"details": "Failed to delete user from database",
			})
			return
		}

		// 3. Cleanup from memory
		clientManager.DeleteWhatsmeowClient(id)
		clientManager.DeleteHTTPClient(id)
		userinfocache.Delete(token)

		// 4. Remove media files
		userDirectory := filepath.Join(s.exPath, "files", id)
		if stat, err := os.Stat(userDirectory); err == nil && stat.IsDir() {
			log.Info().Str("dir", userDirectory).Msg("Deleting media and history files from disk")
			err = os.RemoveAll(userDirectory)
			if err != nil {
				log.Error().Err(err).Str("dir", userDirectory).Msg("Erro ao remover diretório de mídia")
			}
		}

		log.Info().Str("id", id).Str("name", uname).Str("jid", jid).Msg("User deleted successfully")

		// Success response
		s.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"code": http.StatusOK,
			"data": map[string]interface{}{
				"id":   id,
				"name": uname,
				"jid":  jid,
			},
			"success": true,
			"details": "User instance removed completely",
		})
	}
}

func (s *server) Respond(w http.ResponseWriter, r *http.Request, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	dataenvelope := map[string]interface{}{"code": status}
	if err, ok := data.(error); ok {
		dataenvelope["error"] = err.Error()
		dataenvelope["success"] = false
	} else {
		// Try to unmarshal into a map first
		var mydata map[string]interface{}
		if err := json.Unmarshal([]byte(data.(string)), &mydata); err == nil {
			dataenvelope["data"] = mydata
		} else {
			// If unmarshaling into a map fails, try as a slice
			var mySlice []interface{}
			if err := json.Unmarshal([]byte(data.(string)), &mySlice); err == nil {
				dataenvelope["data"] = mySlice
			} else {
				log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Error unmarshalling JSON")
			}
		}
		dataenvelope["success"] = true
	}

	if err := json.NewEncoder(w).Encode(dataenvelope); err != nil {
		panic("respond: " + err.Error())
	}
}

func validateMessageFields(phone string, stanzaid *string, participant *string) (types.JID, error) {

	recipient, ok := parseJID(phone)
	if !ok {
		return types.NewJID("", types.DefaultUserServer), errors.New("Could not parse Phone")
	}

	if stanzaid != nil {
		if participant == nil {
			return types.NewJID("", types.DefaultUserServer), errors.New("Missing Participant in ContextInfo")
		}
	}

	if participant != nil {
		if stanzaid == nil {
			return types.NewJID("", types.DefaultUserServer), errors.New("Missing StanzaID in ContextInfo")
		}
	}

	return recipient, nil
}

func (s *server) SetProxy() http.HandlerFunc {
	type proxyStruct struct {
		ProxyURL string `json:"proxy_url"` // Format: "socks5://user:pass@host:port" or "http://host:port"
		Enable   bool   `json:"enable"`    // Whether to enable or disable proxy
	}

	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		// Check if client exists and is connected

		if clientManager.GetWhatsmeowClient(txtid) != nil && clientManager.GetWhatsmeowClient(txtid).IsConnected() {
			s.Respond(w, r, http.StatusBadRequest, errors.New("cannot set proxy while connected. Please disconnect first"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t proxyStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode payload"))
			return
		}

		// If enable is false, remove proxy configuration
		if !t.Enable {
			_, err = s.db.Exec("UPDATE users SET proxy_url = NULL WHERE id = $1", txtid)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New("failed to remove proxy configuration"))
				return
			}

			response := map[string]interface{}{"Details": "Proxy disabled successfully"}
			responseJson, err := json.Marshal(response)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, err)
			} else {
				s.Respond(w, r, http.StatusOK, string(responseJson))
			}
			return
		}

		// Validate proxy URL
		if t.ProxyURL == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing proxy_url in payload"))
			return
		}

		proxyURL, err := url.Parse(t.ProxyURL)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("invalid proxy URL format"))
			return
		}

		// Only allow http and socks5 proxies
		if proxyURL.Scheme != "http" && proxyURL.Scheme != "socks5" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("only HTTP and SOCKS5 proxies are supported"))
			return
		}

		// Store proxy configuration in database
		_, err = s.db.Exec("UPDATE users SET proxy_url = $1 WHERE id = $2", t.ProxyURL, txtid)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("failed to save proxy configuration"))
			return
		}

		response := map[string]interface{}{
			"Details":  "Proxy configured successfully",
			"ProxyURL": t.ProxyURL,
		}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}
