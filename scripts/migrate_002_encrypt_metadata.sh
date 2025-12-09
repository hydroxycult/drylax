#!/bin/bash
# Migration script for Issue #2: Encrypted Metadata
# Adds encrypted_blob and format_version columns to support v2 format
# Keeps encrypted_content column for backward compatibility with v1 pastes

set -e

DB_PATH="${1:-drylax.db}"

if [ ! -f "$DB_PATH" ]; then
    echo "Error: Database file $DB_PATH not found"
    exit 1
fi

echo "Backing up database to ${DB_PATH}.pre-encrypted-metadata-migration..."
cp "$DB_PATH" "${DB_PATH}.pre-encrypted-metadata-migration"

echo "Checking current schema..."
sqlite3 "$DB_PATH" ".schema pastes" | grep -q "encrypted_blob" && HAS_NEW_COLUMNS=true || HAS_NEW_COLUMNS=false

if [ "$HAS_NEW_COLUMNS" = "true" ]; then
    echo "Already migrated (encrypted_blob column exists)"
    exit 0
fi

echo "Adding encrypted_blob and format_version columns..."

sqlite3 "$DB_PATH" <<EOF
BEGIN TRANSACTION;

-- Add new columns for v2 format
ALTER TABLE pastes ADD COLUMN encrypted_blob BLOB;
ALTER TABLE pastes ADD COLUMN format_version INTEGER DEFAULT 1;

-- Mark existing pastes as v1 format
UPDATE pastes SET format_version = 1 WHERE format_version IS NULL;

COMMIT;
EOF

echo "Migration complete!"
echo "Backup saved at: ${DB_PATH}.pre-encrypted-metadata-migration"
echo ""
echo "IMPORTANT: Schema now supports both v1 (legacy) and v2 (encrypted metadata) formats."
echo "- v1 pastes: encrypted_content column used, metadata in separate columns"
echo "- v2 pastes: encrypted_blob column used, all metadata encrypted"
echo ""
echo "New pastes will be created in v2 format."
echo "Old pastes remain readable in v1 format (backward compatible)."
