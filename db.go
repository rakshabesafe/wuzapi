package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

type DatabaseConfig struct {
	Type     string
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	Path     string
}

func InitializeDatabase(exPath string) (*sqlx.DB, error) {
	config := getDatabaseConfig(exPath)

	if config.Type == "postgres" {
		db, err := initializePostgres(config)
		if err != nil {
			return nil, err
		}
		// Create tables for postgres
		if err := createTables(db, "postgres"); err != nil {
			return nil, fmt.Errorf("failed to create tables for postgres: %w", err)
		}
		return db, nil
	}

	// Default to SQLite
	db, err := initializeSQLite(config)
	if err != nil {
		return nil, err
	}
	// Create tables for sqlite
	if err := createTables(db, "sqlite"); err != nil {
		return nil, fmt.Errorf("failed to create tables for sqlite: %w", err)
	}
	return db, nil
}

func createTables(db *sqlx.DB, dbType string) error {
	// SQL for creating autoreply_modes table
	autoreplyModesTableSQL := `
	CREATE TABLE IF NOT EXISTS autoreply_modes (
		user_id TEXT NOT NULL,
		mode_name TEXT NOT NULL,
		phone_number TEXT NOT NULL,
		message TEXT NOT NULL,
		UNIQUE (user_id, mode_name, phone_number)
	);`

	// SQL for creating active_mode table
	activeModeTableSQL := `
	CREATE TABLE IF NOT EXISTS active_mode (
		user_id TEXT PRIMARY KEY NOT NULL,
		current_mode_name TEXT NULLABLE
	);`

	// Execute table creation statements
	if _, err := db.Exec(autoreplyModesTableSQL); err != nil {
		return fmt.Errorf("failed to create autoreply_modes table: %w", err)
	}
	if _, err := db.Exec(activeModeTableSQL); err != nil {
		return fmt.Errorf("failed to create active_mode table: %w", err)
	}

	// No initial data for active_mode as it's user-specific and populated on demand.

	// Alter users table to add google_contacts_auth_token column
	alterUsersTableSQL := ""
	if dbType == "postgres" {
		alterUsersTableSQL = `ALTER TABLE users ADD COLUMN IF NOT EXISTS google_contacts_auth_token TEXT;`
	} else { // sqlite
		// Check if column exists first for older SQLite versions.
		// For newer SQLite (3.16.0+), ADD COLUMN is idempotent if the column exists.
		// However, to be safe and support potentially older versions, we can check.
		// A simpler approach for tests or if newer SQLite is guaranteed is just:
		// alterUsersTableSQL = `ALTER TABLE users ADD COLUMN google_contacts_auth_token TEXT;`
		// For robustness in a production-like environment, checking PRAGMA is better.

		// Let's use the simpler ALTER TABLE for now, assuming modern SQLite.
		// If this causes issues, a PRAGMA check can be added.
		alterUsersTableSQL = `ALTER TABLE users ADD COLUMN google_contacts_auth_token TEXT;`

		// Check if column exists to avoid error on re-run with older SQLite
		var columnName string
		query := "SELECT name FROM pragma_table_info('users') WHERE name = 'google_contacts_auth_token';"
		err := db.Get(&columnName, query)
		if err == nil && columnName == "google_contacts_auth_token" {
			// Column already exists, no need to alter
			alterUsersTableSQL = ""
		} else if err != nil && err.Error() != "sql: no rows in result set" {
            // An actual error occurred querying pragma_table_info
            return fmt.Errorf("failed to check users table schema: %w", err)
        }
        // If err is "sql: no rows in result set", column doesn't exist, proceed with ALTER.
	}

	if alterUsersTableSQL != "" {
		if _, err := db.Exec(alterUsersTableSQL); err != nil {
			// For SQLite, if the column already exists, this might return an error "duplicate column name"
			// We'll log it and continue if it's that specific error for SQLite.
			if dbType == "sqlite" && strings.Contains(err.Error(), "duplicate column name") {
				// log.Warn().Msg("Column google_contacts_auth_token already exists in users table (SQLite).")
			} else {
				return fmt.Errorf("failed to alter users table to add google_contacts_auth_token: %w", err)
			}
		}
	}


	return nil
}

func getDatabaseConfig(exPath string) DatabaseConfig {
	// Check for PostgreSQL configuration
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")

	// If all PostgreSQL configs are present, use PostgreSQL
	if dbUser != "" && dbPassword != "" && dbName != "" && dbHost != "" && dbPort != "" {
		return DatabaseConfig{
			Type:     "postgres",
			Host:     dbHost,
			Port:     dbPort,
			User:     dbUser,
			Password: dbPassword,
			Name:     dbName,
		}
	}

	// Default to SQLite
	return DatabaseConfig{
		Type: "sqlite",
		Path: filepath.Join(exPath, "dbdata"),
	}
}

func initializePostgres(config DatabaseConfig) (*sqlx.DB, error) {
	dsn := fmt.Sprintf(
		"user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		config.User, config.Password, config.Name, config.Host, config.Port,
	)

	db, err := sqlx.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}
	return db, nil
}

func initializeSQLite(config DatabaseConfig) (*sqlx.DB, error) {
	// Ensure dbdata directory exists
	if err := os.MkdirAll(config.Path, 0751); err != nil {
		return nil, fmt.Errorf("could not create dbdata directory: %w", err)
	}

	dbPath := filepath.Join(config.Path, "users.db")
	db, err := sqlx.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)&_busy_timeout=3000")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}
	return db, nil
}
