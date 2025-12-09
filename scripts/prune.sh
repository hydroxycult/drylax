#!/bin/bash
set -e
DB_PATH="${DATABASE_PATH:-./drylax.db}"
echo "Cleaning up expired pastes from $DB_PATH..."
sqlite3 "$DB_PATH" "DELETE FROM pastes WHERE expires_at < datetime('now');"
DELETED=$(sqlite3 "$DB_PATH" "SELECT changes();")
echo "Deleted $DELETED expired pastes"
