package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
)

type Migration struct {
	ID      int
	Name    string
	UpSQL   string
	DownSQL string
}

var migrations = []Migration{
	{
		ID:    1,
		Name:  "initial_schema",
		UpSQL: initialSchemaSQL,
	},
	{
		ID:   2,
		Name: "add_proxy_url",
		UpSQL: `
            -- PostgreSQL version
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'proxy_url'
                ) THEN
                    ALTER TABLE users ADD COLUMN proxy_url TEXT DEFAULT '';
                END IF;
            END $$;
            
            -- SQLite version (handled in code)
            `,
	},
	{
		ID:    3,
		Name:  "change_id_to_string",
		UpSQL: changeIDToStringSQL,
	},
	{
		ID:    4,
		Name:  "add_autoreplies_table",
		UpSQL: addAutorepliesTableSQLPostgres,
	},
}

const addAutorepliesTableSQLPostgres = `
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'autoreplies') THEN
        CREATE TABLE autoreplies (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            phone_number TEXT NOT NULL,
            reply_body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, phone_number)
        );
    END IF;
END $$;
`

const addAutorepliesTableSQLSQLite = `
CREATE TABLE autoreplies (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    reply_body TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, phone_number)
)
`

const changeIDToStringSQL = `
-- Migration to change ID from integer to random string
DO $$
BEGIN
    -- Only execute if the column is currently integer type
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'id' AND data_type = 'integer'
    ) THEN
        -- For PostgreSQL
        ALTER TABLE users ADD COLUMN new_id TEXT;
		UPDATE users SET new_id = md5(random()::text || id::text || clock_timestamp()::text);
		ALTER TABLE users DROP CONSTRAINT users_pkey;
        ALTER TABLE users DROP COLUMN id CASCADE;
        ALTER TABLE users RENAME COLUMN new_id TO id;
        ALTER TABLE users ALTER COLUMN id SET NOT NULL;
        ALTER TABLE users ADD PRIMARY KEY (id);
    END IF;
END $$;
`

const initialSchemaSQL = `
-- PostgreSQL version
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') THEN
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token TEXT NOT NULL,
            webhook TEXT NOT NULL DEFAULT '',
            jid TEXT NOT NULL DEFAULT '',
            qrcode TEXT NOT NULL DEFAULT '',
            connected INTEGER,
            expiration INTEGER,
            events TEXT NOT NULL DEFAULT 'All',
            proxy_url TEXT DEFAULT ''
        );
    END IF;
END $$;

-- SQLite version (handled in code)
`

// GenerateRandomID creates a random string ID
func GenerateRandomID() (string, error) {
	bytes := make([]byte, 16) // 128 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// Initialize the database with migrations
func initializeSchema(db *sqlx.DB) error {
	// Create migrations table if it doesn't exist
	if err := createMigrationsTable(db); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get already applied migrations
	applied, err := getAppliedMigrations(db)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Apply missing migrations
	for _, migration := range migrations {
		if _, ok := applied[migration.ID]; !ok {
			if err := applyMigration(db, migration); err != nil {
				return fmt.Errorf("failed to apply migration %d: %w", migration.ID, err)
			}
		}
	}

	return nil
}

func createMigrationsTable(db *sqlx.DB) error {
	var tableExists bool
	var err error

	switch db.DriverName() {
	case "postgres":
		err = db.Get(&tableExists, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables 
				WHERE table_name = 'migrations'
			)`)
	case "sqlite":
		err = db.Get(&tableExists, `
			SELECT EXISTS (
				SELECT 1 FROM sqlite_master 
				WHERE type='table' AND name='migrations'
			)`)
	default:
		return fmt.Errorf("unsupported database driver: %s", db.DriverName())
	}

	if err != nil {
		return fmt.Errorf("failed to check migrations table existence: %w", err)
	}

	if tableExists {
		return nil
	}

	_, err = db.Exec(`
		CREATE TABLE migrations (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	return nil
}

func getAppliedMigrations(db *sqlx.DB) (map[int]struct{}, error) {
	applied := make(map[int]struct{})
	var rows []struct {
		ID   int    `db:"id"`
		Name string `db:"name"`
	}

	err := db.Select(&rows, "SELECT id, name FROM migrations ORDER BY id ASC")
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}

	for _, row := range rows {
		applied[row.ID] = struct{}{}
	}

	return applied, nil
}

func applyMigration(db *sqlx.DB, migration Migration) error {
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	if migration.ID == 1 {
		// Handle initial schema creation differently per database
		if db.DriverName() == "sqlite" {
			err = createTableIfNotExistsSQLite(tx, "users", `
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    token TEXT NOT NULL,
                    webhook TEXT NOT NULL DEFAULT '',
                    jid TEXT NOT NULL DEFAULT '',
                    qrcode TEXT NOT NULL DEFAULT '',
                    connected INTEGER,
                    expiration INTEGER,
                    events TEXT NOT NULL DEFAULT 'All',
                    proxy_url TEXT DEFAULT ''
                )`)
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 2 {
		if db.DriverName() == "sqlite" {
			err = addColumnIfNotExistsSQLite(tx, "users", "proxy_url", "TEXT DEFAULT ''")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 3 {
		if db.DriverName() == "sqlite" {
			err = migrateSQLiteIDToString(tx)
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 4 {
		if db.DriverName() == "sqlite" {
			err = createTableIfNotExistsSQLite(tx, "autoreplies", addAutorepliesTableSQLSQLite)
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else {
		_, err = tx.Exec(migration.UpSQL)
	}

	if err != nil {
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	// Record the migration
	if _, err = tx.Exec(`
        INSERT INTO migrations (id, name) 
        VALUES ($1, $2)`, migration.ID, migration.Name); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	return tx.Commit()
}

func createTableIfNotExistsSQLite(tx *sqlx.Tx, tableName, createSQL string) error {
	var exists int
	err := tx.Get(&exists, `
        SELECT COUNT(*) FROM sqlite_master
        WHERE type='table' AND name=?`, tableName)
	if err != nil {
		return err
	}

	if exists == 0 {
		_, err = tx.Exec(createSQL)
		return err
	}
	return nil
}
func sqliteChangeIDType(tx *sqlx.Tx) error {
	// SQLite requires a more complex approach:
	// 1. Create new table with string ID
	// 2. Copy data with new UUIDs
	// 3. Drop old table
	// 4. Rename new table

	// Step 1: Get the current schema
	var tableInfo string
	err := tx.Get(&tableInfo, `
        SELECT sql FROM sqlite_master
        WHERE type='table' AND name='users'`)
	if err != nil {
		return fmt.Errorf("failed to get table info: %w", err)
	}

	// Step 2: Create new table with string ID
	newTableSQL := strings.Replace(tableInfo,
		"CREATE TABLE users (",
		"CREATE TABLE users_new (id TEXT PRIMARY KEY, ", 1)
	newTableSQL = strings.Replace(newTableSQL,
		"id INTEGER PRIMARY KEY AUTOINCREMENT,", "", 1)

	if _, err = tx.Exec(newTableSQL); err != nil {
		return fmt.Errorf("failed to create new table: %w", err)
	}

	// Step 3: Copy data with new UUIDs
	columns, err := getTableColumns(tx, "users")
	if err != nil {
		return fmt.Errorf("failed to get table columns: %w", err)
	}

	// Remove 'id' from columns list
	var filteredColumns []string
	for _, col := range columns {
		if col != "id" {
			filteredColumns = append(filteredColumns, col)
		}
	}

	columnList := strings.Join(filteredColumns, ", ")
	if _, err = tx.Exec(fmt.Sprintf(`
        INSERT INTO users_new (id, %s)
        SELECT gen_random_uuid(), %s FROM users`,
		columnList, columnList)); err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	// Step 4: Drop old table
	if _, err = tx.Exec("DROP TABLE users"); err != nil {
		return fmt.Errorf("failed to drop old table: %w", err)
	}

	// Step 5: Rename new table
	if _, err = tx.Exec("ALTER TABLE users_new RENAME TO users"); err != nil {
		return fmt.Errorf("failed to rename table: %w", err)
	}

	return nil
}

func getTableColumns(tx *sqlx.Tx, tableName string) ([]string, error) {
	var columns []string
	rows, err := tx.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return nil, fmt.Errorf("failed to get table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dfltValue interface{}
		var pk int

		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			return nil, fmt.Errorf("failed to scan column info: %w", err)
		}
		columns = append(columns, name)
	}

	return columns, nil
}

func migrateSQLiteIDToString(tx *sqlx.Tx) error {
	// 1. Check if we need to do the migration
	var currentType string
	err := tx.QueryRow(`
        SELECT type FROM pragma_table_info('users')
        WHERE name = 'id'`).Scan(&currentType)
	if err != nil {
		return fmt.Errorf("failed to check column type: %w", err)
	}

	if currentType != "INTEGER" {
		// No migration needed
		return nil
	}

	// 2. Create new table with string ID
	_, err = tx.Exec(`
        CREATE TABLE users_new (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token TEXT NOT NULL,
            webhook TEXT NOT NULL DEFAULT '',
            jid TEXT NOT NULL DEFAULT '',
            qrcode TEXT NOT NULL DEFAULT '',
            connected INTEGER,
            expiration INTEGER,
            events TEXT NOT NULL DEFAULT 'All',
            proxy_url TEXT DEFAULT ''
        )`)
	if err != nil {
		return fmt.Errorf("failed to create new table: %w", err)
	}

	// 3. Copy data with new UUIDs
	_, err = tx.Exec(`
        INSERT INTO users_new
        SELECT
            hex(randomblob(16)),
            name, token, webhook, jid, qrcode,
            connected, expiration, events, proxy_url 
        FROM users`)
	if err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	// 4. Drop old table
	_, err = tx.Exec(`DROP TABLE users`)
	if err != nil {
		return fmt.Errorf("failed to drop old table: %w", err)
	}

	// 5. Rename new table
	_, err = tx.Exec(`ALTER TABLE users_new RENAME TO users`)
	if err != nil {
		return fmt.Errorf("failed to rename table: %w", err)
	}

	return nil
}

func addColumnIfNotExistsSQLite(tx *sqlx.Tx, tableName, columnName, columnDef string) error {
	var exists int
	err := tx.Get(&exists, `
        SELECT COUNT(*) FROM pragma_table_info(?)
        WHERE name = ?`, tableName, columnName)
	if err != nil {
		return fmt.Errorf("failed to check column existence: %w", err)
	}

	if exists == 0 {
		_, err = tx.Exec(fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN %s %s",
			tableName, columnName, columnDef))
		if err != nil {
			return fmt.Errorf("failed to add column: %w", err)
		}
	}
	return nil
}
