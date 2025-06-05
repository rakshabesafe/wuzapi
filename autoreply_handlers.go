package main

import (
	"database/sql" // Needed for sql.NullString/sql.NullTime if used by handlers here, and for s.db.DriverName()
	"encoding/json"
	"errors"
	"fmt"
	// "io" // Not needed after moving fetchContactsFromGoogleGroupFunc
	"net/http"
	"strings"
	"github.com/rs/zerolog/log" // Used by mode handlers
	// "time" // Used by AutoReplyEntry which is now in autoreply_types.go
)

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

		newId, err := GenerateRandomID()
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate random ID for auto-reply")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to create auto-reply entry"))
			return
		}

		_, err = s.db.Exec("INSERT INTO autoreplies (id, user_id, phone_number, reply_body, last_sent_at) VALUES ($1, $2, $3, $4, $5)", newId, txtid, req.Phone, req.Body, nil)
		if err != nil {
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
			var lastSentAt sql.NullTime
			if err := rows.Scan(&entry.Phone, &entry.Body, &lastSentAt); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Msg("Failed to scan auto-reply row")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to process auto-reply data"))
				return
			}
			if lastSentAt.Valid {
				entry.LastSentAt = &lastSentAt.Time
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
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to process deletion confirmation"))
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

		tx, err := s.db.Beginx()
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to begin transaction for EnableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode"))
			return
		}
		defer tx.Rollback()

		clearAutorepliesQuery := "DELETE FROM autoreplies WHERE user_id = $1"
		if dbType == "sqlite" {
			clearAutorepliesQuery = "DELETE FROM autoreplies WHERE user_id = ?"
		}
		if _, err := tx.Exec(clearAutorepliesQuery, txtid); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to clear autoreplies for EnableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode (clear old)"))
			return
		}

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

		var updateActiveModeQuery string
		if dbType == "postgres" {
			updateActiveModeQuery = `INSERT INTO active_mode (user_id, current_mode_name) VALUES ($1, $2)
                                 ON CONFLICT(user_id) DO UPDATE SET current_mode_name = EXCLUDED.current_mode_name;`
		} else {
			updateActiveModeQuery = `INSERT OR REPLACE INTO active_mode (user_id, current_mode_name) VALUES (?, ?);`
		}
		if _, err := tx.Exec(updateActiveModeQuery, txtid, modeName); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Str("mode_name", modeName).Msg("Failed to update active_mode for EnableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to enable mode (update active)"))
			return
		}

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

		tx, err := s.db.Beginx()
		if err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to begin transaction for DisableMode")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to disable mode"))
			return
		}
		defer tx.Rollback()

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
			clearAutorepliesQuery := "DELETE FROM autoreplies WHERE user_id = $1"
			if dbType == "sqlite" {
				clearAutorepliesQuery = "DELETE FROM autoreplies WHERE user_id = ?"
			}
			if _, err := tx.Exec(clearAutorepliesQuery, txtid); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Msg("Failed to clear autoreplies for DisableMode")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to disable mode (clear replies)"))
				return
			}

			updateActiveModeQuery := "UPDATE active_mode SET current_mode_name = NULL WHERE user_id = $1"
			if dbType == "sqlite" {
				updateActiveModeQuery = "UPDATE active_mode SET current_mode_name = NULL WHERE user_id = ?"
			}
			if _, err := tx.Exec(updateActiveModeQuery, txtid); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Msg("Failed to set active_mode to NULL for DisableMode")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to disable mode (set null)"))
				return
			}

			if err := tx.Commit(); err != nil {
				log.Error().Err(err).Str("user_id", txtid).Msg("Failed to commit transaction for DisableMode")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to disable mode (commit)"))
				return
			}
			response := map[string]string{"detail": fmt.Sprintf("Mode '%s' disabled successfully.", modeName)}
			responseJson, _ := json.Marshal(response)
			s.Respond(w, r, http.StatusOK, string(responseJson))
		} else {
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
			modeNameStr = ""
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

		clearAutorepliesQuery := "DELETE FROM autoreplies WHERE user_id = $1"
		if dbType == "sqlite" {
			clearAutorepliesQuery = "DELETE FROM autoreplies WHERE user_id = ?"
		}
		if _, err := tx.Exec(clearAutorepliesQuery, txtid); err != nil {
			log.Error().Err(err).Str("user_id", txtid).Msg("Failed to clear autoreplies for ClearModes")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to clear modes (clear replies)"))
			return
		}

		var updateActiveModeQuery string
		if dbType == "postgres" {
			updateActiveModeQuery = `INSERT INTO active_mode (user_id, current_mode_name) VALUES ($1, NULL)
                                 ON CONFLICT(user_id) DO UPDATE SET current_mode_name = NULL;`
		} else {
            updateActiveModeQuery = `INSERT INTO active_mode (user_id, current_mode_name) VALUES (?, NULL)
                                     ON CONFLICT(user_id) DO UPDATE SET current_mode_name = NULL;`
		}
        if dbType == "sqlite" {
            res, err_update := tx.Exec("UPDATE active_mode SET current_mode_name = NULL WHERE user_id = ?", txtid)
            if err_update != nil {
                log.Error().Err(err_update).Str("user_id", txtid).Msg("Failed to update active_mode to NULL for ClearModes (SQLite)")
                s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to clear modes (set null)"))
                return
            }
            rowsAffected, _ := res.RowsAffected()
            if rowsAffected == 0 {
                _, err_insert := tx.Exec("INSERT INTO active_mode (user_id, current_mode_name) VALUES (?, NULL)", txtid)
                if err_insert != nil {
                    log.Error().Err(err_insert).Str("user_id", txtid).Msg("Failed to insert into active_mode for ClearModes (SQLite)")
                    s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to clear modes (insert null)"))
                    return
                }
            }
        } else {
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
