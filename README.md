# Economic Data API

A robust API for accessing global economic indicators built with FastAPI and PostgreSQL.

## Overview

This API provides access to various global economic indicators, including:

- GDP growth rates
- Population growth rates
- Education expenditure percentages
- Inflation rates
- Labour force statistics

The system uses JWT token-based authentication to secure endpoints and provides comprehensive data filtering options.

## Architecture

The application consists of two main components:

1. **PostgreSQL Database** - Stores economic indicators data from the World Bank
2. **FastAPI Application** - Provides RESTful API endpoints to access the data

## Setup and Installation

### Prerequisites

- Docker and Docker Compose

### Running the Application

1. Clone the repository:

   ```bash
   git clone https://github.com/shadeiskndr/tgp-api.git
   cd tgp-api
   ```

2. Start the services using Docker Compose:

   ```bash
   docker-compose up -d
   ```

3. The API will be available at http://localhost:8000

## API Documentation

Once the application is running, you can access the interactive API documentation at:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Authentication

Most endpoints require authentication. To obtain a JWT token:

1. Make a POST request to `/api/auth/login` with:

   ```json
   {
     "username": "johndoe",
     "password": "admin"
   }
   ```

2. Use the returned token in the Authorization header for subsequent requests:
   ```
   Authorization: Bearer {your_token}
   ```

### Key Endpoints

- **`/health`**: Health check endpoint (no auth required)
- **`/api/auth/login`**: Obtain JWT token
- **`/api/auth/me`**: Get current user information
- **`/api/data/countries`**: List available countries
- **`/api/data/{category}`**: Get economic data by category
  - Available categories: `gdp`, `population`, `education`, `inflation`, `labour`
  - Supports filtering by country, year, or year range
  - Includes pagination via `limit` and `offset` parameters

## Data Filtering Examples

Get GDP data for a specific country:

```
GET /api/data/gdp?country=USA
```

Get inflation data for a specific year range:

```
GET /api/data/inflation?year_from=2010&year_to=2020
```

Get education data with pagination:

```
GET /api/data/education?limit=10&offset=20
```

## Development

### Environment Variables

- `SECRET_KEY`: JWT signing key
- `DATABASE_URL`: PostgreSQL connection string

### Database Structure

The database contains tables for different economic indicators, all linked to a countries table via country_id.
