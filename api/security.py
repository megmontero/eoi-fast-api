from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyQuery, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    api_key: str  

settings = Settings()

password = settings.api_key

credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no registrado o contraseña errónea.")

credentials_exception_2 = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                        detail="No se han podido validar las credenciales.",
                                        headers={"WWW-Authenticate":"Bearer"})


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# API key header
apikey_security = APIKeyQuery(name="api_key")

def validate_apikey(value: str):
    if(value != password):
        raise credentials_exception

# Auth2    
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS512"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

users_db = {}

class UserSchema(BaseModel):
    username: str
    hashed_password: str
    content_rating: str

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    if username not in users_db:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username")
    return UserSchema(**users_db[username])

def authenticate_user(form_data: OAuth2PasswordRequestForm):
    user = get_user(form_data.username)
    if not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")    

def encode_token(payload: dict):
    try:
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    except InvalidTokenError:
        raise credentials_exception    

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])         
    except InvalidTokenError:
        raise credentials_exception
    
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    user = get_user(data["sub"])  
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta
    payload = {
        **data,
        "exp": expire,
        "cr": user.content_rating  
    }
    return encode_token(payload)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/act4/token")

async def get_validated_active_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception_2
    user = get_user(username)
    return user
