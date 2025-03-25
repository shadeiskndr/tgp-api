#!/bin/bash
set -e

echo "Waiting for PostgreSQL to start..."
until pg_isready -U "$POSTGRES_USER"; do
  sleep 2
done

echo "Restoring database from backup.dump..."
pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" /backup.dump || true

echo "Database restoration complete!"
