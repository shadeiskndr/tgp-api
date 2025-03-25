#!/bin/bash
set -e

echo "Starting PostgreSQL..."
docker-entrypoint.sh postgres &

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
until pg_isready -U "$POSTGRES_USER"; do
  sleep 2
done

# Run the restore script
echo "Restoring database from backup..."
/restore.sh

# Keep PostgreSQL running
wait
