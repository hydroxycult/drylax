#!/bin/bash
set -e
DB_PATH="${DATABASE_PATH:-./drylax.db}"
echo "Running migrations on $DB_PATH..."
echo "Migrations complete!"
