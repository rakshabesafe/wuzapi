package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	// "io" // Not needed if fetchContactsFromGoogleGroupFunc is moved
	"net/http"
	"strings"
	"github.com/rs/zerolog/log"
	// "time" // Already in autoreply_types.go
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

[end of autoreply_handlers.go]
