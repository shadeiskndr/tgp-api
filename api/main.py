from fastapi import FastAPI, Depends, HTTPException, Query, status, HTTPException, Security
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
import os
import jwt
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import time

SECRET_KEY = os.getenv("SECRET_KEY")  # Use a secure key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 30

# Database connection URL
DATABASE_URL = os.getenv("DATABASE_URL")

# Create async engine
engine = create_async_engine(DATABASE_URL, echo=True)

# Create session factory
async_session_maker = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# Dependency to get DB session
async def get_db():
    async with async_session_maker() as session:
        yield session

# FastAPI app
app = FastAPI()

fake_users_db = {
    "johndoe": {"username": "admin@admin.com", "password": "admin"}
}

class Login(BaseModel):
    username: str
    password: str

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    payload = verify_jwt_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    return payload

@app.get("/")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": f"Hello, {current_user['sub']}! You are authenticated."}

@app.post("/api/login")
async def login(user: Login):
    db_user = fake_users_db.get(user.username)
    if not db_user or db_user["password"] != user.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    
    token_data = {"sub": user.username}
    token = create_jwt_token(data=token_data)
    return {"access_token": token, "token_type": "bearer"}

def create_jwt_token(data: dict):
    to_encode = data.copy()
    expire = int(time.time()) + (ACCESS_TOKEN_EXPIRE_SECONDS * 60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_jwt_token(token: str):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Compare the expiration time with the current time
        if decoded_token["exp"] >= int(time.time()):
            return decoded_token
        else:
            return None  # Token is expired
        
    except jwt.PyJWTError:
        return None  # Invalid token or error during decoding
    
# Function to fetch data with optional country filter
async def fetch_data(query: str, db: AsyncSession, country: str = None):
    if country:
        query += " WHERE c.iso_code = :country"
        params = {"country": country.upper()}
    else:
        params = {}

    result = await db.execute(text(query), params)
    data = result.mappings().all()

    if not data:
        raise HTTPException(status_code=404, detail="No data found")

    return data

@app.get("/api/gdp")
async def get_gdp(
    country: str = Query(None, description="Optional country ISO code"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    query = """
        SELECT g.id, g.year, g.gdp_growth_rate, c.country_name, c.iso_code
        FROM gdp_growth g
        JOIN countries c ON g.country_id = c.country_id
    """
    return {"gdp": await fetch_data(query, db, country)}

@app.get("/api/population_growth")
async def get_population(
    country: str = Query(None, description="Optional country ISO code"),
    db: AsyncSession = Depends(get_db)
):
    query = """
        SELECT p.id, p.year, p.population_growth_rate, c.country_name, c.iso_code
        FROM population_growth p
        JOIN countries c ON p.country_id = c.country_id
    """
    return {"population": await fetch_data(query, db, country)}

@app.get("/api/education_expenditure")
async def get_education_expenditure(
    country: str = Query(None, description="Optional country ISO code"),
    db: AsyncSession = Depends(get_db)
):
    query = """
        SELECT e.id, e.year, e.expenditure_percentage, c.country_name, c.iso_code
        FROM gov_expenditure e
        JOIN countries c ON e.country_id = c.country_id
    """
    return {"education_expenditure": await fetch_data(query, db, country)}

@app.get("/api/inflation")
async def get_inflation(
    country: str = Query(None, description="Optional country ISO code"),
    db: AsyncSession = Depends(get_db)
):
    query = """
        SELECT i.id, i.year, i.inflation_rate, c.country_name, c.iso_code
        FROM inflation i
        JOIN countries c ON i.country_id = c.country_id
    """
    return {"inflation": await fetch_data(query, db, country)}

@app.get("/api/labour_force")
async def get_labour_force(
    country: str = Query(None, description="Optional country ISO code"),
    db: AsyncSession = Depends(get_db)
):
    query = """
        SELECT l.id, l.year, l.labour_force_total, c.country_name, c.iso_code
        FROM labour_force l
        JOIN countries c ON l.country_id = c.country_id
    """
    return {"labour_force": await fetch_data(query, db, country)}
