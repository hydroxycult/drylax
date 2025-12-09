#!/bin/bash
# Migration script for Issue #1: IP Hashing
# Renames client_ip column to client_ip_hash in existing databases
# Existing raw IPs will remain in the database - these should be manually
# cleared or will be overwritten by new paste creates

set -e

DB_PATH="${1:-drylax.db}"

if [ ! -f "$DB_PATH" ]; then
    echo "Error: Database file $DB_PATH not found"
    exit 1
fi

echo "Backing up database to ${DB_PATH}.pre-ip-hash-migration..."
cp "$DB_PATH" "${DB_PATH}.pre-ip-hash-migration"

echo "Checking current schema..."
sqlite3 "$DB_PATH" ".schema pastes" | grep -q "client_ip " && HAS_OLD_COLUMN=true || HAS_OLD_COLUMN=false

if [ "$HAS_OLD_COLUMN" = "false" ]; then
    echo "Already migrated (client_ip column not found, client_ip_hash likely exists)"
    exit 0
fi

echo "Migrating client_ip to client_ip_hash..."

# SQLite requires table recreation for column rename
sqlite3 "$DB_PATH" <<EOF
BEGIN TRANSACTION;

-- Create new table with client_ip_hash column
CREATE TABLE pastes_new (
    id TEXT PRIMARY KEY,
    encrypted_content BLOB NOT NULL,
    encrypted_dek BLOB NOT NULL,
    hash TEXT,
    deletion_token_hash TEXT,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    views INTEGER DEFAULT 0,
    client_ip_hash TEXT
);

-- Copy data (client_ip becomes client_ip_hash - raw IPs will be stored temporarily)
INSERT INTO pastes_new
SELECT id, encrypted_content, encrypted_dek, hash, deletion_token_hash,
       created_at, expires_at, views, client_ip
FROM pastes;

-- Replace old table
DROP TABLE pastes;
ALTER TABLE pastes_new RENAME TO pastes;

-- Recreate index
CREATE INDEX idx_expires_at ON pastes(expires_at);

COMMIT;
EOF

echo "Migration complete!"
echo "Backup saved at: ${DB_PATH}.pre-ip-hash-migration"
echo ""
echo "IMPORTANT: Existing pastes have raw IPs in client_ip_hash column."
echo "These will be replaced when new pastes are created."
echo "For privacy, consider running a cleanup script to null out existing IPs:"
echo "  sqlite3 $DB_PATH \"UPDATE pastes SET client_ip_hash = NULL;\""
