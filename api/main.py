from fastapi import FastAPI, Depends, HTTPException, Query, status, Security, APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
import os
import jwt
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import time
import logging
from enum import Enum

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "default-dev-key")  # Default for development
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # More intuitive name

# Database connection URL
DATABASE_URL = os.getenv("DATABASE_URL")

# Create async engine
engine = create_async_engine(DATABASE_URL, echo=True)

# Create session factory
async_session_maker = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# Dependency to get DB session
async def get_db():
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()

# FastAPI app
app = FastAPI(
    title="Economic Data API",
    description="API for accessing global economic indicators",
    version="1.0.0"
)

# Models
class Login(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_at: int

class DataCategory(str, Enum):
    GDP = "gdp"
    POPULATION = "population"
    EDUCATION = "education"
    INFLATION = "inflation"
    LABOUR = "labour"

# User storage - in production, use a database
fake_users_db = {
    "johndoe": {"username": "johndoe", "password": "admin"}
}

# Security
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    logger.info(f"Authenticating request with token: {credentials.credentials[:10]}...")
    try:
        token = credentials.credentials
        payload = verify_jwt_token(token)
        if payload is None:
            logger.warning("Authentication failed: Invalid or expired token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        logger.info(f"Authentication successful for user: {payload['sub']}")
        return payload
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

def create_jwt_token(data: dict):
    to_encode = data.copy()
    expire = int(time.time()) + (ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, expire

def verify_jwt_token(token: str):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Compare the expiration time with the current time
        if decoded_token["exp"] >= int(time.time()):
            return decoded_token
        else:
            logger.warning("Token has expired")
            return None  # Token is expired
        
    except jwt.PyJWTError as e:
        logger.warning(f"JWT error: {str(e)}")
        return None  # Invalid token or error during decoding

# API Routers
auth_router = APIRouter(prefix="/api/auth", tags=["Authentication"])
data_router = APIRouter(prefix="/api/data", tags=["Economic Data"])

@auth_router.post("/login", response_model=Token)
async def login(user: Login):
    """
    Authenticate a user and return a JWT token
    """
    db_user = fake_users_db.get(user.username)
    if not db_user or db_user["password"] != user.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token_data = {"sub": user.username}
    token, expires_at = create_jwt_token(data=token_data)
    return {"access_token": token, "token_type": "bearer", "expires_at": expires_at}

@auth_router.get("/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """
    Get information about the currently authenticated user
    """
    return {"username": current_user['sub']}

# Centralized data fetching logic
async def fetch_data(
    db: AsyncSession, 
    category: DataCategory, 
    country: Optional[str] = None,
    year: Optional[int] = None,
    year_from: Optional[int] = None,
    year_to: Optional[int] = None,
    limit: int = 100,
    offset: int = 0
):
    """Fetch data with filtering, sorting and pagination"""
    
    # Define base queries for each category
    queries = {
        DataCategory.GDP: """
            SELECT g.id, g.year, g.gdp_growth_rate AS value, c.country_name, c.iso_code
            FROM gdp_growth g
            JOIN countries c ON g.country_id = c.country_id
        """,
        DataCategory.POPULATION: """
            SELECT p.id, p.year, p.population_growth_rate AS value, c.country_name, c.iso_code
            FROM population_growth p
            JOIN countries c ON p.country_id = c.country_id
        """,
        DataCategory.EDUCATION: """
            SELECT e.id, e.year, e.expenditure_percentage AS value, c.country_name, c.iso_code
            FROM gov_expenditure e
            JOIN countries c ON e.country_id = c.country_id
        """,
        DataCategory.INFLATION: """
            SELECT i.id, i.year, i.inflation_rate AS value, c.country_name, c.iso_code
            FROM inflation i
            JOIN countries c ON i.country_id = c.country_id
        """,
        DataCategory.LABOUR: """
            SELECT l.id, l.year, l.labour_force_total AS value, c.country_name, c.iso_code
            FROM labour_force l
            JOIN countries c ON l.country_id = c.country_id
        """
    }
    
    # Get the base query for the requested category
    query = queries.get(category)
    if not query:
        raise HTTPException(status_code=400, detail=f"Invalid category: {category}")
    
    # Build where clause with parameters
    where_clauses = []
    params = {}
    
    if country:
        where_clauses.append("c.iso_code = :country")
        params["country"] = country.upper()
    
    # Determine table prefix for year columns
    table_prefix = category[0].lower() if category != DataCategory.LABOUR else "l"
    
    # Handle year range filtering
    if year:
        # Single year filter (for backward compatibility)
        where_clauses.append(f"{table_prefix}.year = :year")
        params["year"] = year
    else:
        # Year range filtering
        if year_from:
            where_clauses.append(f"{table_prefix}.year >= :year_from")
            params["year_from"] = year_from
        
        if year_to:
            where_clauses.append(f"{table_prefix}.year <= :year_to")
            params["year_to"] = year_to
    
    # Add WHERE clause if needed
    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)
    
    # Add order by, limit and offset
    query += " ORDER BY c.country_name, year DESC LIMIT :limit OFFSET :offset"
    params["limit"] = limit
    params["offset"] = offset

    try:
        # Execute query
        result = await db.execute(text(query), params)
        data = result.mappings().all()
        
        # Count total results without pagination
        count_query = f"SELECT COUNT(*) as total FROM ({queries.get(category)}"
        if where_clauses:
            count_query += " WHERE " + " AND ".join(where_clauses)
        count_query += ") AS count_query"
        
        count_result = await db.execute(text(count_query), params)
        total_count = count_result.scalar_one()
        
        if not data:
            return {"data": [], "total": 0, "limit": limit, "offset": offset}
            
        return {
            "data": [dict(row) for row in data],
            "total": total_count,
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        logger.error(f"Database error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@data_router.get("/countries")
async def get_countries(
    limit: int = Query(100, ge=1, le=1000, description="Number of results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get the list of all available countries with pagination
    """
    try:
        # Query for paginated results
        query = """
            SELECT iso_code, country_name 
            FROM countries 
            ORDER BY country_name
            LIMIT :limit OFFSET :offset
        """
        result = await db.execute(text(query), {"limit": limit, "offset": offset})
        countries = result.mappings().all()
        
        # Count total results
        count_query = "SELECT COUNT(*) as total FROM countries"
        count_result = await db.execute(text(count_query))
        total_count = count_result.scalar_one()
        
        # Format response consistent with other endpoints
        return {
            "data": [{"code": country["iso_code"], "name": country["country_name"]} for country in countries],
            "total": total_count,
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        logger.error(f"Database error when fetching countries: {str(e)}")
        # Generic error message that doesn't expose database details
        raise HTTPException(status_code=500, detail="An error occurred while retrieving countries")

@data_router.get("/{category}")
async def get_economic_data(
    category: DataCategory,
    country: Optional[str] = Query(None, description="Optional country ISO code"),
    year: Optional[int] = Query(None, description="Filter by specific year"),
    year_from: Optional[int] = Query(None, description="Filter from year (inclusive)"),
    year_to: Optional[int] = Query(None, description="Filter to year (inclusive)"),
    limit: int = Query(100, ge=1, le=1000, description="Number of results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get economic data by category with optional filtering
    """
    logger.info(f"{category.value.capitalize()} endpoint accessed by user: {current_user['sub']}")
    
    result = await fetch_data(
        db=db,
        category=category,
        country=country,
        year=year,
        year_from=year_from,
        year_to=year_to,
        limit=limit,
        offset=offset
    )
    
    return result

# Health check endpoint (no auth required)
@app.get("/health", tags=["Health"])
async def health_check():
    """Check if the API is running"""
    return {"status": "ok", "timestamp": int(time.time())}

# Root endpoint (requires auth)
@app.get("/", tags=["Root"])
async def root(current_user: dict = Depends(get_current_user)):
    """Root endpoint requiring authentication"""
    return {
        "message": f"Hello, {current_user['sub']}! You are authenticated.",
        "documentation": "/docs"
    }

# Include routers
app.include_router(auth_router)
app.include_router(data_router)

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred"}
    )
