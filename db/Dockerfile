# Use the official PostgreSQL base image
FROM postgres:latest

# Set environment variables for PostgreSQL
ENV POSTGRES_USER=admin
ENV POSTGRES_PASSWORD=admin
ENV POSTGRES_DB=world_bank_db

# Copy the dump file into the container
COPY world_bank_db.dump /backup.dump

# Copy the restore script
COPY restore.sh /restore.sh
RUN chmod +x /restore.sh

# Expose PostgreSQL port
EXPOSE 5432

# Use a custom entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
