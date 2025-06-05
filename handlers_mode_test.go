package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

var testServer *httptest.Server
var testDB *sqlx.DB
var testRouter *mux.Router
var S *server // Global server instance for tests

const testAdminToken = "test_admin_token"
const testUserToken1 = "test_user_token_1"
const testUserID1 = "testuser1"
const testUserToken2 = "test_user_token_2"
const testUserID2 = "testuser2"

// Mock GenerateRandomID for predictable IDs in tests if needed,
// for now, we will rely on checking other fields.

func TestMain(m *testing.M) {
	// Suppress log output during tests
	zerolog.SetGlobalLevel(zerolog.Disabled)

	// Setup test database
	var err error
	testDB, err = setupTestDB()
	if err != nil {
		fmt.Printf("Failed to set up test database: %v\n", err)
		os.Exit(1)
	}
	defer testDB.Close()

	// Setup server
	ex, _ := os.Executable()
	exPath := filepath.Dir(ex)

	adminTokenVar := testAdminToken // directly use const
	S = &server{
		db:            testDB,
		router:        mux.NewRouter(),
		exPath:        exPath,
		whatsmeowOpts: defaultWhatsmeowOptions(),
	}
	adminToken = &adminTokenVar // Assign to global adminToken used by server

	// Initialize userinfocache (global variable used by authalice)
	userinfocache = cache.New(cache.NoExpiration, 10*time.Minute)
	// Pre-populate cache for test users
	userinfocache.Set(testUserToken1, Values{map[string]string{"Id": testUserID1, "Name": "Test User 1"}}, cache.NoExpiration)
	userinfocache.Set(testUserToken2, Values{map[string]string{"Id": testUserID2, "Name": "Test User 2"}}, cache.NoExpiration)

	// Initialize killchannel (global variable used by server)
	killchannel = make(map[string]chan bool)

	// Initialize clientManager (global variable)
    clientManager = NewClientManager()


	S.routes() // Use the actual routes
	testRouter = S.router
	testServer = httptest.NewServer(testRouter)
	defer testServer.Close()

	// Run tests
	exitCode := m.Run()
	os.Exit(exitCode)
}

func setupTestDB() (*sqlx.DB, error) {
	// Use an in-memory SQLite database for tests
	// Ensure the path includes parameters for foreign keys and busy timeout for consistency
	db, err := sqlx.Open("sqlite", "file:test_wuzapi.db?mode=memory&cache=shared&_pragma=foreign_keys(1)&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory sqlite database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping test database: %w", err)
	}

	// Create tables - adapting from db.go's createTables
	// We need to ensure this is compatible with SQLite for tests
	tablesSQL := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			name TEXT,
			token TEXT UNIQUE,
			webhook TEXT,
			jid TEXT,
			events TEXT,
			proxy_url TEXT,
			qrcode TEXT,
			connected INTEGER DEFAULT 0,
			expiration INTEGER
		);`,
		`CREATE TABLE IF NOT EXISTS autoreply_modes (
			user_id TEXT NOT NULL,
			mode_name TEXT NOT NULL,
			phone_number TEXT NOT NULL,
			message TEXT NOT NULL,
			UNIQUE (user_id, mode_name, phone_number)
		);`,
		`CREATE TABLE IF NOT EXISTS active_mode (
			user_id TEXT PRIMARY KEY NOT NULL,
			current_mode_name TEXT NULLABLE
		);`,
		`CREATE TABLE IF NOT EXISTS autoreplies (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            reply_body TEXT NOT NULL,
            last_sent_at TIMESTAMP NULLABLE,
            UNIQUE (user_id, phone_number)
        );`, // Added from original migration
	}

	for _, sql := range tablesSQL {
		if _, err := db.Exec(sql); err != nil {
			return nil, fmt.Errorf("failed to execute table creation SQL: %s, error: %w", sql, err)
		}
	}
	return db, nil
}

func clearAllTables(db *sqlx.DB) {
	tables := []string{"autoreply_modes", "active_mode", "autoreplies", "users"}
	for _, table := range tables {
		// For SQLite, DELETE FROM should be fine. For PostgreSQL, TRUNCATE would be faster.
		// Since this is SQLite for tests, DELETE FROM is okay.
		_, err := db.Exec(fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			fmt.Printf("Failed to clear table %s: %v\n", table, err)
		}
	}
	// Re-populate userinfocache for test users after clearing users table
	userinfocache.Flush() // Clear existing cache
	userinfocache.Set(testUserToken1, Values{map[string]string{"Id": testUserID1, "Name": "Test User 1"}}, cache.NoExpiration)
	userinfocache.Set(testUserToken2, Values{map[string]string{"Id": testUserID2, "Name": "Test User 2"}}, cache.NoExpiration)

	// We also need to add the test users to the DB for authalice to find them if cache misses (though we pre-populate)
	_, _ = db.Exec("INSERT INTO users (id, name, token) VALUES (?, ?, ?)", testUserID1, "Test User 1", testUserToken1)
	_, _ = db.Exec("INSERT INTO users (id, name, token) VALUES (?, ?, ?)", testUserID2, "Test User 2", testUserToken2)

}


func newAuthenticatedRequest(t *testing.T, method, path string, body io.Reader, userToken string, userID string) *http.Request {
	req, err := http.NewRequest(method, testServer.URL+path, body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Simulate authalice middleware by setting userinfo in context
	// In a real scenario, authalice would fetch this from DB or cache based on token
	// For testing, we directly create the Values struct and put it in context.
	// The token in header is mostly for completeness of the request object.
	if userID != "" {
		req.Header.Set("token", userToken) // authalice checks this token
		userInfo := Values{m: map[string]string{
			"Id":    userID,
			"Name":  "Test User", // Or fetch/map from userID if needed
			"Token": userToken,
			// Add other fields like Jid, Webhook etc. if your handlers depend on them
		}}
		ctx := context.WithValue(req.Context(), "userinfo", userInfo)
		req = req.WithContext(ctx)
	}
	return req
}


// TestAddModeAutoreply covers POST /mode/autoreply
func TestAddModeAutoreply(t *testing.T) {
	defer clearAllTables(testDB)

	tests := []struct {
		name           string
		userID         string
		userToken      string
		payload        interface{}
		expectedStatus int
		expectedBody   string // Can be a regex or partial match
		dbChecks       func(t *testing.T, userID string)
	}{
		{
			name:      "Successful new mode addition",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload: ModeAutoreplyRequest{ModeName: "Work", Phone: "111222333", Message: "Working remotely"},
			expectedStatus: http.StatusCreated,
			expectedBody:   `"detail":"Mode autoreply added/updated successfully"`,
			dbChecks: func(t *testing.T, userID string) {
				var count int
				err := testDB.Get(&count, "SELECT COUNT(*) FROM autoreply_modes WHERE user_id = ? AND mode_name = 'work' AND phone_number = '111222333'", userID)
				require.NoError(t, err)
				assert.Equal(t, 1, count, "Expected 1 entry in DB")
			},
		},
		{
			name:      "Update existing mode message",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload: ModeAutoreplyRequest{ModeName: "Work", Phone: "111222333", Message: "Working from office today"}, // Same mode/phone
			expectedStatus: http.StatusCreated, // Upsert behavior
			expectedBody:   `"detail":"Mode autoreply added/updated successfully"`,
			dbChecks: func(t *testing.T, userID string) {
				var msg string
				err := testDB.Get(&msg, "SELECT message FROM autoreply_modes WHERE user_id = ? AND mode_name = 'work' AND phone_number = '111222333'", userID)
				require.NoError(t, err)
				assert.Equal(t, "Working from office today", msg)
			},
		},
		{
			name:      "Invalid mode name - special chars",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload: ModeAutoreplyRequest{ModeName: "Work!", Phone: "123", Message: "Msg"},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `"error":"Invalid ModeName: must be alphanumeric"`,
		},
		{
			name:      "Missing Phone",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload: ModeAutoreplyRequest{ModeName: "ValidMode", Phone: "", Message: "Msg"},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `"error":"Missing Phone in Payload"`,
		},
		{
			name:      "User specificity - User 2 adds same mode name as User 1",
			userID:    testUserID2,
			userToken: testUserToken2,
			payload: ModeAutoreplyRequest{ModeName: "Work", Phone: "444555666", Message: "User 2 Work Message"},
			expectedStatus: http.StatusCreated,
			expectedBody:   `"detail":"Mode autoreply added/updated successfully"`,
			dbChecks: func(t *testing.T, userID string) {
				var countUser1, countUser2 int
				err := testDB.Get(&countUser1, "SELECT COUNT(*) FROM autoreply_modes WHERE user_id = ? AND mode_name = 'work'", testUserID1)
				require.NoError(t, err)
				assert.True(t, countUser1 >= 1, "User 1 should still have their 'work' mode entries")

				err = testDB.Get(&countUser2, "SELECT COUNT(*) FROM autoreply_modes WHERE user_id = ? AND mode_name = 'work' AND phone_number = '444555666'", testUserID2)
				require.NoError(t, err)
				assert.Equal(t, 1, countUser2, "User 2 should have their 'work' mode entry")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// For tests that depend on prior state (like update), ensure that state exists
			if tc.name == "Update existing mode message" {
				setupPayload := ModeAutoreplyRequest{ModeName: "Work", Phone: "111222333", Message: "Initial message"}
				jsonBody, _ := json.Marshal(setupPayload)
				req := newAuthenticatedRequest(t, "POST", "/autoreply/mode", bytes.NewBuffer(jsonBody), testUserToken1, testUserID1)
				rr := httptest.NewRecorder()
				testRouter.ServeHTTP(rr, req) // Use testRouter directly
				require.Equal(t, http.StatusCreated, rr.Code)
			}


			jsonBody, err := json.Marshal(tc.payload)
			require.NoError(t, err)

			req := newAuthenticatedRequest(t, "POST", "/autoreply/mode", bytes.NewBuffer(jsonBody), tc.userToken, tc.userID)
			rr := httptest.NewRecorder()
			testRouter.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			bodyString := rr.Body.String()
			assert.Contains(t, bodyString, tc.expectedBody, "Response body mismatch")

			if tc.dbChecks != nil {
				tc.dbChecks(t, tc.userID)
			}
			// Clean up only this user's data if needed for next sub-test, or rely on defer clearAllTables
			// clearUserSpecificData(testDB, tc.userID, "autoreply_modes")
		})
	}
}

// TestDeleteModeAutoreply covers DELETE /mode/autoreply
func TestDeleteModeAutoreply(t *testing.T) {
	defer clearAllTables(testDB)

	// Setup initial data for user1
	_, err := testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "holiday", "123", "On holiday")
	require.NoError(t, err)
	_, err = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "holiday", "456", "Still on holiday")
	require.NoError(t, err)
	_, err = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "work", "789", "Working")
	require.NoError(t, err)


	tests := []struct {
		name           string
		userID         string
		userToken      string
		payload        interface{}
		expectedStatus int
		expectedDetailRegex string // Regex for detail message
		dbChecks       func(t *testing.T, userID string)
	}{
		{
			name:      "Delete specific phone from mode",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ModeAutoreplyDeleteRequest{ModeName: "holiday", Phone: "123"},
			expectedStatus: http.StatusOK,
			expectedDetailRegex: `1 autoreply entry\(s\) deleted for mode 'holiday'`,
			dbChecks: func(t *testing.T, userID string) {
				var count int
				err := testDB.Get(&count, "SELECT COUNT(*) FROM autoreply_modes WHERE user_id = ? AND mode_name = 'holiday' AND phone_number = '123'", userID)
				require.NoError(t, err)
				assert.Equal(t, 0, count)
				err = testDB.Get(&count, "SELECT COUNT(*) FROM autoreply_modes WHERE user_id = ? AND mode_name = 'holiday' AND phone_number = '456'", userID)
				require.NoError(t, err)
				assert.Equal(t, 1, count) // Other phone for same mode should remain
			},
		},
		{
			name:      "Delete all phones for a mode",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ModeAutoreplyDeleteRequest{ModeName: "holiday"}, // No phone specified
			expectedStatus: http.StatusOK,
			// After previous test, only '456' is left in 'holiday' mode
			expectedDetailRegex: `1 autoreply entry\(s\) deleted for mode 'holiday'`,
			dbChecks: func(t *testing.T, userID string) {
				var count int
				err := testDB.Get(&count, "SELECT COUNT(*) FROM autoreply_modes WHERE user_id = ? AND mode_name = 'holiday'", userID)
				require.NoError(t, err)
				assert.Equal(t, 0, count)
			},
		},
		{
			name:      "Delete non-existent phone from existing mode",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ModeAutoreplyDeleteRequest{ModeName: "work", Phone: "000"},
			expectedStatus: http.StatusOK,
			expectedDetailRegex: `No autoreply entries found or deleted for mode 'work'`,
		},
		{
			name:      "Delete non-existent mode",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ModeAutoreplyDeleteRequest{ModeName: "nonexistent"},
			expectedStatus: http.StatusOK,
			expectedDetailRegex: `No autoreply entries found or deleted for mode 'nonexistent'`,
		},
		{
			name:      "Invalid mode name",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ModeAutoreplyDeleteRequest{ModeName: "work!"},
			expectedStatus: http.StatusBadRequest,
			expectedDetailRegex: `"error":"Invalid ModeName: must be alphanumeric"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonBody, err := json.Marshal(tc.payload)
			require.NoError(t, err)

			req := newAuthenticatedRequest(t, "DELETE", "/autoreply/mode", bytes.NewBuffer(jsonBody), tc.userToken, tc.userID)
			rr := httptest.NewRecorder()
			testRouter.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			bodyString := rr.Body.String()

			match, _ := regexp.MatchString(tc.expectedDetailRegex, bodyString)
			assert.True(t, match, "Response body detail mismatch. Expected regex: %s, Got: %s", tc.expectedDetailRegex, bodyString)


			if tc.dbChecks != nil {
				tc.dbChecks(t, tc.userID)
			}
		})
	}
}


// TestGetModeAutoreplies covers GET /mode/autoreply
func TestGetModeAutoreplies(t *testing.T) {
	defer clearAllTables(testDB)

	// Setup data for user1
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "travel", "111", "Away travelling")
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "travel", "222", "Still travelling")
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "meeting", "333", "In a meeting")
	// Setup data for user2
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID2, "travel", "999", "User 2 travelling")


	tests := []struct {
		name           string
		userID         string
		userToken      string
		modeNameQuery  string // e.g., "?modeName=travel" or ""
		expectedStatus int
		expectedCount  int // Number of entries expected in the "data" array
		expectedContentPart string // A part of the content to check if count > 0
	}{
		{
			name:      "Get all modes for user1",
			userID:    testUserID1,
			userToken: testUserToken1,
			modeNameQuery:  "",
			expectedStatus: http.StatusOK,
			expectedCount:  3,
			expectedContentPart: `"ModeName":"travel"`,
		},
		{
			name:      "Get specific mode 'travel' for user1",
			userID:    testUserID1,
			userToken: testUserToken1,
			modeNameQuery:  "?modeName=travel",
			expectedStatus: http.StatusOK,
			expectedCount:  2,
			expectedContentPart: `"Phone":"111"`,
		},
		{
			name:      "Get specific mode 'meeting' for user1",
			userID:    testUserID1,
			userToken: testUserToken1,
			modeNameQuery:  "?modeName=meeting",
			expectedStatus: http.StatusOK,
			expectedCount:  1,
			expectedContentPart: `"Message":"In a meeting"`,
		},
		{
			name:      "Get non-existent mode for user1",
			userID:    testUserID1,
			userToken: testUserToken1,
			modeNameQuery:  "?modeName=nonexistent",
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
		{
			name:      "Get modes for user2 (should only get user2's data)",
			userID:    testUserID2,
			userToken: testUserToken2,
			modeNameQuery:  "",
			expectedStatus: http.StatusOK,
			expectedCount:  1,
			expectedContentPart: `"Phone":"999"`,
		},
		{
			name:      "Get modes for user with no modes configured",
			userID:    "userwithnomodes", // Assume this user has no data
			userToken: "tokenforuserwithnomodes",
			modeNameQuery:  "",
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
		{
			name:      "Invalid modeName query param",
			userID:    testUserID1,
			userToken: testUserToken1,
			modeNameQuery:  "?modeName=invalid!",
			expectedStatus: http.StatusBadRequest,
			expectedContentPart: `"error":"Invalid modeName parameter: must be alphanumeric"`,
		},
	}
	// Add the temporary user for the "no modes" test
	userinfocache.Set("tokenforuserwithnomodes", Values{map[string]string{"Id": "userwithnomodes", "Name": "No Modes User"}}, cache.NoExpiration)
	_, _ = testDB.Exec("INSERT INTO users (id, name, token) VALUES (?, ?, ?)", "userwithnomodes", "No Modes User", "tokenforuserwithnomodes")


	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newAuthenticatedRequest(t, "GET", "/autoreply/mode"+tc.modeNameQuery, nil, tc.userToken, tc.userID)
			rr := httptest.NewRecorder()
			testRouter.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			bodyString := rr.Body.String()
			if tc.expectedStatus == http.StatusOK {
				var responseData struct {
					Data    []ModeAutoreplyEntry `json:"data"`
					Success bool                 `json:"success"`
					Code    int                  `json:"code"`
				}
				err := json.Unmarshal([]byte(bodyString), &responseData)
				require.NoError(t, err, "Failed to unmarshal response: %s", bodyString)
				assert.True(t, responseData.Success)
				assert.Equal(t, tc.expectedStatus, responseData.Code)
				if assert.NotNil(t, responseData.Data) {
					assert.Len(t, responseData.Data, tc.expectedCount)
					if tc.expectedCount > 0 && tc.expectedContentPart != "" {
						assert.Contains(t, bodyString, tc.expectedContentPart, "Response body content mismatch")
					}
				}
			} else {
				// For error responses, check the error message part
				if tc.expectedContentPart != "" {
					assert.Contains(t, bodyString, tc.expectedContentPart, "Error response body mismatch")
				}
			}
		})
	}
}

// TestEnableMode covers POST /mode/enablemode
func TestEnableMode(t *testing.T) {
	defer clearAllTables(testDB)

	// Setup: User1 has 'vacation' mode with 2 entries. User2 has 'vacation' mode with 1 entry.
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "vacation", "111", "User1 Vacation 1")
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "vacation", "222", "User1 Vacation 2")
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "empty_mode", "777", "this should be cleared") // For testing clearing
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID2, "vacation", "999", "User2 Vacation")

	tests := []struct {
		name            string
		userID          string
		userToken       string
		payload         EnableModeRequest
		expectedStatus  int
		expectedDetailRegex string
		dbChecks        func(t *testing.T, userID string)
	}{
		{
			name:      "Enable valid mode for User1",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   EnableModeRequest{ModeName: "vacation"},
			expectedStatus: http.StatusOK,
			expectedDetailRegex: `Mode 'vacation' enabled successfully. 2 autoreplies activated.`,
			dbChecks: func(t *testing.T, userID string) {
				// Check active_mode
				var activeMode sql.NullString
				err := testDB.Get(&activeMode, "SELECT current_mode_name FROM active_mode WHERE user_id = ?", userID)
				require.NoError(t, err)
				require.True(t, activeMode.Valid, "current_mode_name should be valid")
				assert.Equal(t, "vacation", activeMode.String)

				// Check autoreplies table
				var replies []AutoReplyEntry
				err = testDB.Select(&replies, "SELECT phone_number, reply_body FROM autoreplies WHERE user_id = ?", userID)
				require.NoError(t, err)
				assert.Len(t, replies, 2)
				// Check if correct entries were added (order might not be guaranteed)
				expectedReplies := map[string]string{"111": "User1 Vacation 1", "222": "User1 Vacation 2"}
				foundReplies := make(map[string]string)
				for _, r := range replies {
					foundReplies[r.Phone] = r.Body
				}
				assert.Equal(t, expectedReplies, foundReplies)
			},
		},
		{
			name:      "Enable mode with no entries",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   EnableModeRequest{ModeName: "work"}, // Assume 'work' mode has no entries for user1
			expectedStatus: http.StatusOK,
			expectedDetailRegex: `Mode 'work' enabled successfully. 0 autoreplies activated.`,
			dbChecks: func(t *testing.T, userID string) {
				var activeMode sql.NullString
				err := testDB.Get(&activeMode, "SELECT current_mode_name FROM active_mode WHERE user_id = ?", userID)
				require.NoError(t, err)
				require.True(t, activeMode.Valid)
				assert.Equal(t, "work", activeMode.String)
				var count int
				err = testDB.Get(&count, "SELECT COUNT(*) FROM autoreplies WHERE user_id = ?", userID)
				require.NoError(t, err)
				assert.Equal(t, 0, count)
			},
		},
		{
			name:      "Enable non-existent mode", // The handler logic currently creates the mode in active_mode and activates 0 replies.
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   EnableModeRequest{ModeName: "nonexistent"},
			expectedStatus: http.StatusOK,
			expectedDetailRegex: `Mode 'nonexistent' enabled successfully. 0 autoreplies activated.`,
		},
		{
			name:      "Invalid mode name",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   EnableModeRequest{ModeName: "bad!"},
			expectedStatus: http.StatusBadRequest,
			expectedDetailRegex: `"error":"Invalid ModeName: must be alphanumeric"`,
		},
		{
			name:      "User specificity - Enable User2's mode",
			userID:    testUserID2,
			userToken: testUserToken2,
			payload:   EnableModeRequest{ModeName: "vacation"},
			expectedStatus: http.StatusOK,
			expectedDetailRegex: `Mode 'vacation' enabled successfully. 1 autoreplies activated.`,
			dbChecks: func(t *testing.T, userID string) {
				// Check active_mode for User2
				var activeModeUser2 sql.NullString
				err := testDB.Get(&activeModeUser2, "SELECT current_mode_name FROM active_mode WHERE user_id = ?", testUserID2)
				require.NoError(t, err)
				require.True(t, activeModeUser2.Valid)
				assert.Equal(t, "vacation", activeModeUser2.String)
				// Check autoreplies for User2
				var repliesUser2 []AutoReplyEntry
				err = testDB.Select(&repliesUser2, "SELECT phone_number, reply_body FROM autoreplies WHERE user_id = ?", testUserID2)
				require.NoError(t, err)
				assert.Len(t, repliesUser2, 1)
				assert.Equal(t, "999", repliesUser2[0].Phone)

				// Ensure User1's active_mode (if set by a previous subtest) is not affected or is as expected
                // This requires careful sequencing or resetting User1's state if subtests are not isolated.
                // For now, we assume subtests might affect each other if not reset.
                // Let's check User1's autoreplies count, it should be 0 if "work" or "nonexistent" was enabled for user1 previously.
                var user1AutoreplyCount int
                _ = testDB.Get(&user1AutoreplyCount, "SELECT COUNT(*) from autoreplies WHERE user_id=?", testUserID1)
                assert.Equal(t, 0, user1AutoreplyCount, "User1's autoreplies should be 0 if previous test ran")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// If a test depends on a clean slate for a user (e.g. to check initial enabling)
			// you might need to clear that user's active_mode and autoreplies here.
			if tc.name == "Enable valid mode for User1" { // Reset before this specific one
				_, _ = testDB.Exec("DELETE FROM active_mode WHERE user_id = ?", testUserID1)
				_, _ = testDB.Exec("DELETE FROM autoreplies WHERE user_id = ?", testUserID1)
			}


			jsonBody, err := json.Marshal(tc.payload)
			require.NoError(t, err)

			req := newAuthenticatedRequest(t, "POST", "/autoreply/enablemode", bytes.NewBuffer(jsonBody), tc.userToken, tc.userID)
			rr := httptest.NewRecorder()
			testRouter.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			bodyString := rr.Body.String()
			match, _ := regexp.MatchString(tc.expectedDetailRegex, bodyString)
			assert.True(t, match, "Response body detail mismatch. Expected regex: %s, Got: %s", tc.expectedDetailRegex, bodyString)

			if tc.dbChecks != nil {
				tc.dbChecks(t, tc.userID)
			}
		})
	}
}

// TestDisableMode covers POST /mode/disablemode
func TestDisableMode(t *testing.T) {
	defer clearAllTables(testDB)

	// Setup: User1 has 'activemode' active and some autoreplies. User2 has no active mode.
	_, _ = testDB.Exec("INSERT INTO active_mode (user_id, current_mode_name) VALUES (?, ?)", testUserID1, "activemode")
	_, _ = testDB.Exec("INSERT INTO autoreplies (id, user_id, phone_number, reply_body) VALUES (?, ?, ?, ?)", "reply1", testUserID1, "123", "Active reply")


	tests := []struct {
		name            string
		userID          string
		userToken       string
		payload         DisableModeRequest
		expectedStatus  int
		expectedDetailRegex string
		dbChecks        func(t *testing.T, userID string)
	}{
		{
			name:      "Disable currently active mode",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   DisableModeRequest{ModeName: "activemode"},
			expectedStatus: http.StatusOK,
			expectedDetailRegex: `Mode 'activemode' disabled successfully.`,
			dbChecks: func(t *testing.T, userID string) {
				var activeMode sql.NullString
				err := testDB.Get(&activeMode, "SELECT current_mode_name FROM active_mode WHERE user_id = ?", userID)
				if err != nil && err != sql.ErrNoRows { require.NoError(t, err) } // Allow ErrNoRows if row is deleted
				assert.False(t, activeMode.Valid, "current_mode_name should be NULL or row gone")

				var count int
				err = testDB.Get(&count, "SELECT COUNT(*) FROM autoreplies WHERE user_id = ?", userID)
				require.NoError(t, err)
				assert.Equal(t, 0, count, "Autoreplies should be cleared")
			},
		},
		{
			name:      "Disable a mode that is not active",
			userID:    testUserID1, // User1's mode is now NULL from previous test
			userToken: testUserToken1,
			payload:   DisableModeRequest{ModeName: "someothermode"},
			expectedStatus: http.StatusOK,
			expectedDetailRegex: `Mode 'someothermode' was not active or does not exist. No changes made.`,
			dbChecks: func(t *testing.T, userID string) {
				var activeMode sql.NullString
				// Ensure active_mode is still NULL (or row doesn't exist)
				err := testDB.Get(&activeMode, "SELECT current_mode_name FROM active_mode WHERE user_id = ?", userID)
				if err != sql.ErrNoRows { // If row exists, it must be NULL
					require.NoError(t, err)
					assert.False(t, activeMode.Valid)
				}
			},
		},
		{
			name:      "Disable non-existent mode for user with no active mode",
			userID:    testUserID2, // User2 has no active mode initially
			userToken: testUserToken2,
			payload:   DisableModeRequest{ModeName: "nonexistent"},
			expectedStatus: http.StatusOK,
			expectedDetailRegex: `Mode 'nonexistent' was not active or does not exist. No changes made.`,
		},
		{
			name:      "Invalid mode name",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   DisableModeRequest{ModeName: "bad!"},
			expectedStatus: http.StatusBadRequest,
			expectedDetailRegex: `"error":"Invalid ModeName: must be alphanumeric"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonBody, err := json.Marshal(tc.payload)
			require.NoError(t, err)

			req := newAuthenticatedRequest(t, "POST", "/autoreply/disablemode", bytes.NewBuffer(jsonBody), tc.userToken, tc.userID)
			rr := httptest.NewRecorder()
			testRouter.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			bodyString := rr.Body.String()
			match, _ := regexp.MatchString(tc.expectedDetailRegex, bodyString)
			assert.True(t, match, "Response body detail mismatch. Expected regex: %s, Got: %s", tc.expectedDetailRegex, bodyString)

			if tc.dbChecks != nil {
				tc.dbChecks(t, tc.userID)
			}
		})
	}
}

// TestGetCurrentMode covers GET /mode/currentmode
func TestGetCurrentMode(t *testing.T) {
	defer clearAllTables(testDB)

	// Setup: User1 has 'holiday' active. User2 has no entry in active_mode. User3 has entry but NULL.
	_, _ = testDB.Exec("INSERT INTO active_mode (user_id, current_mode_name) VALUES (?, ?)", testUserID1, "holiday")

    // User testUserID2 has no entry in active_mode

    // User "testuser3" for NULL mode
    testUserID3 := "testuser3"
    testUserToken3 := "test_user_token_3"
    userinfocache.Set(testUserToken3, Values{map[string]string{"Id": testUserID3, "Name": "Test User 3"}}, cache.NoExpiration)
	_, _ = testDB.Exec("INSERT INTO users (id, name, token) VALUES (?, ?, ?)", testUserID3, "Test User 3", testUserToken3)
    _, _ = testDB.Exec("INSERT INTO active_mode (user_id, current_mode_name) VALUES (?, NULL)", testUserID3)


	tests := []struct {
		name            string
		userID          string
		userToken       string
		expectedStatus  int
		expectedMode    interface{} // string or nil
	}{
		{
			name:      "Get active mode for User1",
			userID:    testUserID1,
			userToken: testUserToken1,
			expectedStatus: http.StatusOK,
			expectedMode:   "holiday",
		},
		{
			name:      "Get active mode for User2 (no entry)",
			userID:    testUserID2,
			userToken: testUserToken2,
			expectedStatus: http.StatusOK,
			expectedMode:   nil, // Expecting null if no mode is active
		},
        {
			name:      "Get active mode for User3 (entry is NULL)",
			userID:    testUserID3,
			userToken: testUserToken3,
			expectedStatus: http.StatusOK,
			expectedMode:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newAuthenticatedRequest(t, "GET", "/autoreply/currentmode", nil, tc.userToken, tc.userID)
			rr := httptest.NewRecorder()
			testRouter.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			var response struct {
				Data struct {
					CurrentModeName interface{} `json:"current_mode_name"`
				} `json:"data"`
				Success bool `json:"success"`
			}
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.True(t, response.Success)
			assert.Equal(t, tc.expectedMode, response.Data.CurrentModeName)
		})
	}
}

// TestClearModes covers POST /mode/clear
func TestClearModes(t *testing.T) {
	defer clearAllTables(testDB)

	// Setup: User1 has 'work' active and some autoreplies. User2 has no active mode and no autoreplies.
	_, _ = testDB.Exec("INSERT INTO active_mode (user_id, current_mode_name) VALUES (?, ?)", testUserID1, "work")
	_, _ = testDB.Exec("INSERT INTO autoreplies (id, user_id, phone_number, reply_body) VALUES (?, ?, ?, ?)", "reply_work", testUserID1, "789", "Working")

	tests := []struct {
		name            string
		userID          string
		userToken       string
		expectedStatus  int
		expectedDetail  string
		dbChecks        func(t *testing.T, userID string)
	}{
		{
			name:      "Clear when a mode is active for User1",
			userID:    testUserID1,
			userToken: testUserToken1,
			expectedStatus: http.StatusOK,
			expectedDetail: "All modes cleared and current mode deactivated successfully.",
			dbChecks: func(t *testing.T, userID string) {
				var activeMode sql.NullString
				err := testDB.Get(&activeMode, "SELECT current_mode_name FROM active_mode WHERE user_id = ?", userID)
				// After clear, the row in active_mode should exist and be NULL (due to handler logic)
				require.NoError(t, err, "Should still have a row in active_mode or it was correctly handled")
				assert.False(t, activeMode.Valid, "current_mode_name should be NULL")

				var count int
				err = testDB.Get(&count, "SELECT COUNT(*) FROM autoreplies WHERE user_id = ?", userID)
				require.NoError(t, err)
				assert.Equal(t, 0, count, "Autoreplies should be cleared")
			},
		},
		{
			name:      "Clear when no mode is active for User2",
			userID:    testUserID2,
			userToken: testUserToken2,
			expectedStatus: http.StatusOK,
			expectedDetail: "All modes cleared and current mode deactivated successfully.",
			dbChecks: func(t *testing.T, userID string) {
				var activeMode sql.NullString
				err := testDB.Get(&activeMode, "SELECT current_mode_name FROM active_mode WHERE user_id = ?", userID)
                // After clear, User2 should have an entry in active_mode set to NULL
				require.NoError(t, err, "User should have an entry in active_mode after clear")
				assert.False(t, activeMode.Valid, "current_mode_name should be NULL")

				var count int
				err = testDB.Get(&count, "SELECT COUNT(*) FROM autoreplies WHERE user_id = ?", userID)
				require.NoError(t, err)
				assert.Equal(t, 0, count, "Autoreplies should remain 0")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newAuthenticatedRequest(t, "POST", "/autoreply/clearmode", nil, tc.userToken, tc.userID)
			rr := httptest.NewRecorder()
			testRouter.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			var response struct {
				Data struct {
					Detail string `json:"detail"`
				} `json:"data"`
				Success bool `json:"success"`
			}
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.True(t, response.Success)
			assert.Equal(t, tc.expectedDetail, response.Data.Detail)

			if tc.dbChecks != nil {
				tc.dbChecks(t, tc.userID)
			}
		})
	}
}

func TestIsValidModeName(t *testing.T) {
	assert.True(t, isValidModeName("work"))
	assert.True(t, isValidModeName("Work123"))
	assert.True(t, isValidModeName("OFFICE"))
	assert.False(t, isValidModeName("work!"))
	assert.False(t, isValidModeName("work mode"))
	assert.False(t, isValidModeName(""))
	assert.False(t, isValidModeName(" test"))
}

func TestNormalizePhoneNumber(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      string
		expectError   bool
		expectedError string
	}{
		{"empty input", "", "", true, "phone number is empty after cleaning"},
		{"short input", "12345", "", true, "phone number '12345' has invalid length after normalization"},
		{"long input", "1234567890123456", "", true, "phone number '1234567890123456' has invalid length after normalization"},
		{"invalid chars", "abc", "", true, "phone number is empty after cleaning"},
		{"valid 10 digit (India)", "9876543210", "919876543210", false, ""},
		{"valid 10 digit with spaces (India)", " 98765 43210 ", "919876543210", false, ""},
		{"valid US with + and hyphens", "+1-555-123-4567", "15551234567", false, ""},
		{"valid US with () and spaces", " (555) 876-5432 ", "5558765432", false, ""}, // Assuming non-prefixed 10-digit becomes Indian
		{"valid UK with + and hyphens", "+44-20-1234-5678", "442012345678", false, ""},
		{"just +", "+", "", true, "phone number is empty after cleaning"},
		{"valid with extension (not handled, cleaned)", "+1234567890x123", "1234567890123", false, ""}, // x123 is cleaned out
		{"leading zeros", "0011234567890", "11234567890", false, ""}, // Assuming 00 is not a country code here, simple cleaning
		{"already normalized with 91", "919988776655", "919988776655", false, ""},
		{"already normalized US", "18005551212", "18005551212", false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			normalized, err := normalizePhoneNumber(tc.input)
			if tc.expectError {
				assert.Error(t, err)
				if tc.expectedError != "" {
					assert.Contains(t, err.Error(), tc.expectedError)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, normalized)
			}
		})
	}
	// Correcting a specific case based on current normalizePhoneNumber logic
    // " (555) 876-5432 " will become "5558765432", and then prefixed with "91"
    // because it's 10 digits and does not start with '+'.
    t.Run("US number without plus becomes indian", func(t *testing.T){
        normalized, err := normalizePhoneNumber(" (555) 876-5432 ")
        assert.NoError(t, err)
        assert.Equal(t, "915558765432", normalized)
    })
}


// Helper function to set google_contacts_auth_token for a user
func setGoogleTokenForUser(t *testing.T, userID, token string) {
	_, err := testDB.Exec("UPDATE users SET google_contacts_auth_token = ? WHERE id = ?", token, userID)
	require.NoError(t, err, "Failed to set Google token for user %s", userID)
}


func TestSetGoogleContactsAuthToken(t *testing.T) {
	defer clearAllTables(testDB)

	tests := []struct {
		name           string
		userID         string
		userToken      string
		payload        AuthTokenRequest
		expectedStatus int
		expectedBody   string
		dbCheck        func(t *testing.T, userID string, expectedToken string)
	}{
		{
			name:      "Successful token storage",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   AuthTokenRequest{AuthToken: "sample-google-token-123"},
			expectedStatus: http.StatusOK,
			expectedBody:   `"detail":"Auth token stored successfully"`,
			dbCheck: func(t *testing.T, userID string, expectedToken string) {
				var token sql.NullString
				err := testDB.Get(&token, "SELECT google_contacts_auth_token FROM users WHERE id = ?", userID)
				require.NoError(t, err)
				require.True(t, token.Valid)
				assert.Equal(t, expectedToken, token.String)
			},
		},
		{
			name:      "Empty token in payload",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   AuthTokenRequest{AuthToken: "  "}, // Whitespace only
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `"error":"Missing AuthToken in Payload"`,
		},
		{
			name:      "Update existing token",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   AuthTokenRequest{AuthToken: "new-updated-token-456"},
			expectedStatus: http.StatusOK,
			expectedBody:   `"detail":"Auth token stored successfully"`,
			dbCheck: func(t *testing.T, userID string, expectedToken string) {
				var token sql.NullString
				err := testDB.Get(&token, "SELECT google_contacts_auth_token FROM users WHERE id = ?", userID)
				require.NoError(t, err)
				require.True(t, token.Valid)
				assert.Equal(t, expectedToken, token.String)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// For "Update existing token", first set an initial token
			if tc.name == "Update existing token" {
				setGoogleTokenForUser(t, testUserID1, "initial-token-000")
			}

			jsonBody, err := json.Marshal(tc.payload)
			require.NoError(t, err)

			req := newAuthenticatedRequest(t, "POST", "/autoreply/contactgroupauth", bytes.NewBuffer(jsonBody), tc.userToken, tc.userID)
			rr := httptest.NewRecorder()
			testRouter.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tc.expectedBody)

			if tc.dbCheck != nil {
				tc.dbCheck(t, tc.userID, tc.payload.AuthToken)
			}
		})
	}
}


func TestAddContactGroupToMode(t *testing.T) {
	defer clearAllTables(testDB)

	// Pre-set auth token for testUserID1
	setGoogleTokenForUser(t, testUserID1, "valid-google-token")

	// Store original fetch function to restore after tests
	originalFetchContactsFunc := fetchContactsFromGoogleGroupFunc
	defer func() { fetchContactsFromGoogleGroupFunc = originalFetchContactsFunc }()

	tests := []struct {
		name            string
		userID          string
		userToken       string
		payload         ContactGroupRequest
		expectedStatus  int
		expectedBodyRegex string // Regex for detailed message checks
		dbChecks        func(t *testing.T, userID, modeName string)
	}{
		{
			name:      "Successful add - default group",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupRequest{ModeName: "Holiday", GroupName: "Default Google Group", Message: "Away on holiday!"},
			expectedStatus: http.StatusOK,
			expectedBodyRegex: `3 contacts processed and added/updated for mode 'holiday'. 3 contacts skipped.`, // Based on placeholder's default
			dbChecks: func(t *testing.T, userID, modeName string) {
				var count int
				// Expected normalized numbers from placeholder: "11234567890", "919876543210", "442012345678"
				err := testDB.Get(&count, "SELECT COUNT(*) FROM autoreply_modes WHERE user_id = ? AND mode_name = ?", userID, strings.ToLower(modeName))
				require.NoError(t, err)
				assert.Equal(t, 3, count, "Should have 3 valid contacts added")

				var msg string
				err = testDB.Get(&msg, "SELECT message FROM autoreply_modes WHERE user_id = ? AND mode_name = ? AND phone_number = ?", userID, strings.ToLower(modeName), "919876543210")
				require.NoError(t, err)
				assert.Equal(t, "Away on holiday!", msg)
			},
		},
		{
			name:      "Add with 'work contacts' group",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupRequest{ModeName: "WorkMode", GroupName: "Work Contacts", Message: "Busy with work!"},
			expectedStatus: http.StatusOK,
			expectedBodyRegex: `2 contacts processed and added/updated for mode 'workmode'. 0 contacts skipped.`,
			dbChecks: func(t *testing.T, userID, modeName string) {
				var entries []ModeAutoreplyEntry
				err := testDB.Select(&entries, "SELECT phone_number, message FROM autoreply_modes WHERE user_id = ? AND mode_name = ?", userID, strings.ToLower(modeName))
				require.NoError(t, err)
				assert.Len(t, entries, 2)
				expectedPhones := map[string]bool{"15551234567": false, "915558765432": false} // 5558765432 becomes 915558765432
				for _, e := range entries {
					if _, ok := expectedPhones[e.Phone]; ok {
						expectedPhones[e.Phone] = true
						assert.Equal(t, "Busy with work!", e.Message)
					}
				}
				for phone, found := range expectedPhones {
					assert.True(t, found, "Expected phone %s not found", phone)
				}
			},
		},
		{
			name:      "Token not configured for user",
			userID:    testUserID2, // UserID2 has no token set yet
			userToken: testUserToken2,
			payload:   ContactGroupRequest{ModeName: "AnyMode", GroupName: "AnyGroup", Message: "Msg"},
			expectedStatus: http.StatusForbidden,
			expectedBodyRegex: `"error":"Google Contacts API token not configured`,
		},
		{
			name:      "Invalid ModeName",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupRequest{ModeName: "Invalid!", GroupName: "AnyGroup", Message: "Msg"},
			expectedStatus: http.StatusBadRequest,
			expectedBodyRegex: `"error":"Invalid ModeName: must be alphanumeric"`,
		},
		{
			name:      "Missing GroupName",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupRequest{ModeName: "ValidMode", GroupName: " ", Message: "Msg"},
			expectedStatus: http.StatusBadRequest,
			expectedBodyRegex: `"error":"Missing GroupName in Payload"`,
		},
		{
			name:      "fetchContactsFromGoogleGroup returns error",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupRequest{ModeName: "ErrorTest", GroupName: "errorgroup", Message: "This will fail"},
			expectedStatus: http.StatusInternalServerError,
			expectedBodyRegex: `"error":"Failed to process contact group"`,
		},
		{
			name:      "fetchContactsFromGoogleGroup returns empty list",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupRequest{ModeName: "EmptyTest", GroupName: "emptygroup", Message: "No one here"},
			expectedStatus: http.StatusOK,
			expectedBodyRegex: `No contacts found or processed for group 'emptygroup'.`, // Adjusted to expect detail, not error
		},
		{
			name:      "Google API returns UNAUTHENTICATED error",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupRequest{ModeName: "AuthTest", GroupName: "auth_error_group", Message: "Test"},
			expectedStatus: http.StatusForbidden,
			expectedBodyRegex: `"error":"Failed to authenticate with Google Contacts API. Please check your token or re-authenticate via /autoreply/contactgroupauth."`,
		},
		{
			name:      "Google API returns PERMISSION_DENIED error",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupRequest{ModeName: "PermTest", GroupName: "perm_denied_group", Message: "Test"},
			expectedStatus: http.StatusForbidden,
			expectedBodyRegex: `"error":"Failed to authenticate with Google Contacts API. Please check your token or re-authenticate via /autoreply/contactgroupauth."`,
		},
		{
			name:      "Google API returns group not found error",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupRequest{ModeName: "NotFoundTest", GroupName: "non_existent_google_group", Message: "Test"},
			expectedStatus: http.StatusNotFound,
			expectedBodyRegex: `"error":"Specified contact group 'non_existent_google_group' not found."`,
		},
		{
			name:      "Google API returns generic error",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupRequest{ModeName: "GenericErrorTest", GroupName: "generic_google_api_error_group", Message: "Test"},
			expectedStatus: http.StatusInternalServerError,
			expectedBodyRegex: `"error":"Error processing contacts from Google group."`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock for fetchContactsFromGoogleGroupFunc
			fetchContactsFromGoogleGroupFunc = func(authToken string, groupName string, forUserLog string) ([]map[string]string, error) {
				if groupName == "Default Google Group" {
					return []map[string]string{
						{"name": "Test Contact 1", "phoneNumber": "+11234567890"},
						{"name": "Test Contact 2", "phoneNumber": "9876543210"},
						{"name": "Test Contact 3", "phoneNumber": "invalid-number"},
						{"name": "Test Contact 4", "phoneNumber": "+44-20-1234-5678"},
						{"name": "Test Contact 5", "phoneNumber": "12345"},
						{"name": "Test Contact 6", "phoneNumber": ""},
					}, nil
				}
				if groupName == "Work Contacts" {
					return []map[string]string{
						{"name": "Alice Smith", "phoneNumber": "+15551234567"},
						{"name": "Bob Johnson", "phoneNumber": " (555) 876-5432"},
					}, nil
				}
				if groupName == "errorgroup" {
					return nil, errors.New("simulated error fetching contacts from Google Group")
				}
				if groupName == "emptygroup" {
					return []map[string]string{}, nil
				}
				if groupName == "auth_error_group" {
					return nil, errors.New("Google API error: Some message (Status: UNAUTHENTICATED)")
				}
				if groupName == "perm_denied_group" {
					return nil, errors.New("Google API error: Some message (Status: PERMISSION_DENIED)")
				}
				if groupName == "non_existent_google_group" {
					return nil, fmt.Errorf("contact group '%s' not found for user %s", groupName, forUserLog)
				}
				if groupName == "generic_google_api_error_group" {
					return nil, errors.New("some other Google API error")
				}
				return nil, fmt.Errorf("unexpected groupName in mock: %s", groupName)
			}

			jsonBody, err := json.Marshal(tc.payload)
			require.NoError(t, err)

			req := newAuthenticatedRequest(t, "POST", "/autoreply/contactgroup", bytes.NewBuffer(jsonBody), tc.userToken, tc.userID)
			rr := httptest.NewRecorder()
			testRouter.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			bodyString := rr.Body.String()
			match, _ := regexp.MatchString(tc.expectedBodyRegex, bodyString)
			assert.True(t, match, "Response body regex mismatch.\nExpected regex: %s\nGot: %s", tc.expectedBodyRegex, bodyString)

			if tc.dbChecks != nil {
				tc.dbChecks(t, tc.userID, tc.payload.ModeName)
			}
		})
	}
}


func TestDeleteContactGroupFromMode(t *testing.T) {
	defer clearAllTables(testDB)

	// Pre-set auth token for testUserID1
	setGoogleTokenForUser(t, testUserID1, "valid-google-token")
	// Setup initial data for User1, Mode "cleaningmode"
	// Contacts from default mock: "11234567890", "919876543210", "442012345678"
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "cleaningmode", "11234567890", "To be deleted")
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "cleaningmode", "919876543210", "Also deleted") // This will be 91919876543210 after normalization in test
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "cleaningmode", "442012345678", "This one too")
	_, _ = testDB.Exec("INSERT INTO autoreply_modes (user_id, mode_name, phone_number, message) VALUES (?, ?, ?, ?)", testUserID1, "cleaningmode", "0000000000", "Keep this one") // Not in placeholder group

	tests := []struct{
		name            string
		userID          string
		userToken       string
		payload         ContactGroupDeleteRequest
		expectedStatus  int
		expectedBodyRegex string
		dbChecks        func(t *testing.T, userID, modeName string)
	}{
		{
			name:      "Successful delete - default group",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupDeleteRequest{ModeName: "CleaningMode", GroupName: "Default Google Group"}, // Uses default placeholder
			expectedStatus: http.StatusOK,
	// Mock has 6 contacts, 3 invalid/empty, 3 valid. So 3 processed, 3 deleted.
			expectedBodyRegex: `3 contacts from group 'Default Google Group' processed for deletion from mode 'cleaningmode'. 3 entries actually deleted. 3 contacts skipped.`,
			dbChecks: func(t *testing.T, userID, modeName string) {
				var count int
				err := testDB.Get(&count, "SELECT COUNT(*) FROM autoreply_modes WHERE user_id = ? AND mode_name = ?", userID, strings.ToLower(modeName))
				require.NoError(t, err)
				assert.Equal(t, 1, count, "Only the '0000000000' contact should remain")

				var phone string
		// Ensure the phone number that remains is the one not in the mocked group
		err = testDB.Get(&phone, "SELECT phone_number FROM autoreply_modes WHERE user_id = ? AND mode_name = ? AND phone_number = '0000000000'", userID, strings.ToLower(modeName))
		require.NoError(t, err, "The non-group contact '0000000000' should still exist")
				assert.Equal(t, "0000000000", phone)
			},
		},
		{
			name:      "Token not configured for user",
			userID:    testUserID2,
			userToken: testUserToken2,
			payload:   ContactGroupDeleteRequest{ModeName: "AnyMode", GroupName: "AnyGroup"},
			expectedStatus: http.StatusForbidden,
			expectedBodyRegex: `"error":"Google Contacts API token not configured`,
		},
		{
			name:      "Invalid ModeName for delete",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupDeleteRequest{ModeName: "Invalid!", GroupName: "AnyGroup"},
			expectedStatus: http.StatusBadRequest,
			expectedBodyRegex: `"error":"Invalid ModeName: must be alphanumeric"`,
		},
		{
			name:      "fetchContactsFromGoogleGroup returns error on delete",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupDeleteRequest{ModeName: "ErrorTest", GroupName: "errorgroup"},
			expectedStatus: http.StatusInternalServerError,
			expectedBodyRegex: `"error":"Failed to process contact group for deletion"`,
		},
		{
			name:      "Delete with empty contact group",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupDeleteRequest{ModeName: "AnyMode", GroupName: "emptygroup"},
			expectedStatus: http.StatusOK, // Adjusted: 200 OK with detail message
			expectedBodyRegex: `No contacts found in group 'emptygroup' to process for deletion.`,
		},
		{
			name:      "Google API UNAUTHENTICATED error on delete",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupDeleteRequest{ModeName: "AuthTestDelete", GroupName: "auth_error_group_delete"},
			expectedStatus: http.StatusForbidden,
			expectedBodyRegex: `"error":"Failed to authenticate with Google Contacts API. Please check your token or re-authenticate via /autoreply/contactgroupauth."`,
		},
		{
			name:      "Google API PERMISSION_DENIED error on delete",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupDeleteRequest{ModeName: "PermTestDelete", GroupName: "perm_denied_group_delete"},
			expectedStatus: http.StatusForbidden,
			expectedBodyRegex: `"error":"Failed to authenticate with Google Contacts API. Please check your token or re-authenticate via /autoreply/contactgroupauth."`,
		},
		{
			name:      "Google API group not found error on delete",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupDeleteRequest{ModeName: "NotFoundTestDelete", GroupName: "non_existent_google_group_delete"},
			expectedStatus: http.StatusNotFound,
			expectedBodyRegex: `"error":"Specified contact group 'non_existent_google_group_delete' not found."`,
		},
		{
			name:      "Google API generic error on delete",
			userID:    testUserID1,
			userToken: testUserToken1,
			payload:   ContactGroupDeleteRequest{ModeName: "GenericErrorTestDelete", GroupName: "generic_google_api_error_group_delete"},
			expectedStatus: http.StatusInternalServerError,
			expectedBodyRegex: `"error":"Error processing contacts from Google group for deletion."`,
		},
	}
	// Store original fetch function to restore after tests
	originalFetchContactsFunc := fetchContactsFromGoogleGroupFunc
	defer func() { fetchContactsFromGoogleGroupFunc = originalFetchContactsFunc }()


	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock for fetchContactsFromGoogleGroupFunc for delete tests
			fetchContactsFromGoogleGroupFunc = func(authToken string, groupName string, forUserLog string) ([]map[string]string, error) {
				if groupName == "Default Google Group" { // Used in "Successful delete - default group"
					return []map[string]string{
						{"name": "Test Contact 1", "phoneNumber": "+11234567890"},
						{"name": "Test Contact 2", "phoneNumber": "9876543210"},
						{"name": "Test Contact 3", "phoneNumber": "invalid-number"},
						{"name": "Test Contact 4", "phoneNumber": "+44-20-1234-5678"},
						{"name": "Test Contact 5", "phoneNumber": "12345"},
						{"name": "Test Contact 6", "phoneNumber": ""},
					}, nil
				}
				if groupName == "emptygroup" {
					return []map[string]string{}, nil
				}
				if groupName == "auth_error_group_delete" {
					return nil, errors.New("Google API error: Some message (Status: UNAUTHENTICATED)")
				}
				if groupName == "perm_denied_group_delete" {
					return nil, errors.New("Google API error: Some message (Status: PERMISSION_DENIED)")
				}
				if groupName == "non_existent_google_group_delete" {
					return nil, fmt.Errorf("contact group '%s' not found for user %s", groupName, forUserLog)
				}
				if groupName == "generic_google_api_error_group_delete" {
					return nil, errors.New("some other Google API error for delete")
				}
				// This case is for "fetchContactsFromGoogleGroup returns error on delete"
				if groupName == "errorgroup" {
					return nil, errors.New("simulated error fetching contacts from Google Group for delete")
				}
				return nil, fmt.Errorf("unexpected groupName in mock for delete: %s", groupName)
			}


			jsonBody, err := json.Marshal(tc.payload)
			require.NoError(t, err)

			req := newAuthenticatedRequest(t, "DELETE", "/autoreply/contactgroup", bytes.NewBuffer(jsonBody), tc.userToken, tc.userID)
			rr := httptest.NewRecorder()
			testRouter.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			bodyString := rr.Body.String()
			match, _ := regexp.MatchString(tc.expectedBodyRegex, bodyString)
			assert.True(t, match, "Response body regex mismatch.\nExpected regex: %s\nGot: %s", tc.expectedBodyRegex, bodyString)

			if tc.dbChecks != nil {
				tc.dbChecks(t, tc.userID, tc.payload.ModeName)
			}
		})
	}
}


// Helper to get string value from sql.NullString for assertions
func nullStringValue(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return "" // Or some other indicator for NULL if needed
}
