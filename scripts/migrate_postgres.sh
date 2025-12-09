#!/bin/bash
set -euo pipefail
echo "Creating Postgres migration from SQLite..."
psql ${POSTGRES_URL} <<SQL
CREATE TABLE IF NOT EXISTS pastes (
    id TEXT PRIMARY KEY,
    encrypted_content BYTEA NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    hash TEXT,
    deletion_token_hash TEXT,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    views INTEGER DEFAULT 0,
    client_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_expires_at ON pastes(expires_at);
CREATE TABLE IF NOT EXISTS migration_log (
    id SERIAL PRIMARY KEY,
    migrated_at TIMESTAMP DEFAULT NOW(),
    source_db TEXT,
    rows_migrated INTEGER
);
SQL
echo "Postgres schema created successfully"
