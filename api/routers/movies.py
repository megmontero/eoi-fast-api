import csv
import json
from typing import Annotated
from fastapi import APIRouter, HTTPException, Query, status, Depends
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from db import redis
from security import authenticate_user, create_access_token, get_password_hash, get_validated_active_user, validate_apikey, apikey_security, users_db, OAuth2PasswordRequestForm, UserSchema
from passlib.hash import bcrypt

router = APIRouter(tags=["movies"], prefix="/act4")


#######################################################################################################################################################################
# Modelos de datos
#######################################################################################################################################################################

class MovieSchema(BaseModel):
    movie_title: str = Field(description="Título de la película", example="Inception")
    content_rating: str = Field(description="Clasificación de edad de la película", example="PG-13")
    genres: str = Field(description="Géneros de la película", example="Action, Sci-Fi")
    tomatometer_rating: int = Field(description="Valoración de Rotten Tomatoes (0 a 100)", example=87)
    original_release_date: str = Field(description="Fecha de estreno de la película", example="2010-07-16")

class HTTPExceptionModel(BaseModel):
    detail: str = Field(description="Mensaje de error", example="Credenciales no válidas")

class Token(BaseModel):
    access_token: str
    token_type: str

#######################################################################################################################################################################
# Evento de inicio para cargar las películas en Redis
#######################################################################################################################################################################

@router.lifespan_context("startup")
def startup_event():
    """
    Cargar los datos de las películas en Redis al iniciar la aplicación.
    Cada `content_rating` será una clave en Redis y contendrá una lista de películas con esa clasificación.
    """
    try:
        # Limpiar todas las claves en Redis al iniciar
        redis.flushall()
        
        # Abrir y leer el archivo CSV de películas
        with open('files/rotten_tomatoes_movies.csv') as file:
            reader = csv.DictReader(file)
            
            # Agrupar las películas por `content_rating`
            movies_by_rating = {}
            
            for row in reader:
                if row['tomatometer_status'] == 'Certified-Fresh' and row['content_rating'] != 'NR':
                    movie_data = {
                        "movie_title": row['movie_title'],
                        "content_rating": row['content_rating'],
                        "genres": row['genres'],
                        "tomatometer_rating": int(float(row['tomatometer_rating'])),
                        "original_release_date": row['original_release_date']
                    }
                    
                    # Obtener el content_rating de la película
                    rating = row['content_rating']
                    
                    # Agregar la película al grupo correspondiente en el diccionario
                    if rating in movies_by_rating:
                        movies_by_rating[rating].append(movie_data)
                    else:
                        movies_by_rating[rating] = [movie_data]

            # Guardar cada grupo de películas en Redis usando `content_rating` como clave
            for rating, movies in movies_by_rating.items():
                redis.set(rating, json.dumps(movies))

    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al cargar películas en Redis"
        )
    
#######################################################################################################################################################################
# Endpoint para registrar un nuevo usuario
#######################################################################################################################################################################


@router.post("/register", 
             summary="Registrar un nuevo usuario",
             status_code=status.HTTP_204_NO_CONTENT,
             responses={
                 status.HTTP_204_NO_CONTENT: {"description": "Usuario registrado exitosamente"},
                 status.HTTP_400_BAD_REQUEST: {"description": "Usuario ya registrado", "model": HTTPExceptionModel},
                 status.HTTP_401_UNAUTHORIZED: {"description": "Credenciales no válidas", "model": HTTPExceptionModel}
                 })

def register_user(username: str = Query(description="Nombre de usuario, mínimo 4 caracteres y la primera letra debe ser mayúscula", min_length=4, pattern="^[A-Z].*", example="JohnDoe"),
                  password: str = Query(description="Contraseña con longitud mínima de 8 caracteres", min_length=8, example="password123"),
                  content_rating: str = Query(description="Calificación de edad", pattern="^(G|PG|PG-13|R|NC-17)$", example="PG"),
                  apikey: str = Depends(apikey_security)):
    """
    Registra un nuevo usuario en la base de datos en memoria.
    Verifica si el nombre de usuario ya existe, hashea la contraseña y almacena los datos en memoria.
    """
    validate_apikey(apikey)
    
    # Verificar si el usuario ya está registrado
    if username in users_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario ya está registrado")

    # Hash de la contraseña usando bcrypt
    hashed_password = get_password_hash(password)

    # Almacenar el usuario en la base de datos en memoria
    users_db[username] = {
        "username": username,
        "hashed_password": hashed_password,
        "content_rating": content_rating
    }
    return HTTPException(status_code=status.HTTP_204_NO_CONTENT, detail="Usuario registrado exitosamente")

#######################################################################################################################################################################
# Auth2
#######################################################################################################################################################################

@router.post("/token", 
             summary="Login para obtener un nuevo token",
             responses={
                 status.HTTP_200_OK: {"description": "Credenciales validadas. Token devuelto.", "model": Token},
                 status.HTTP_401_UNAUTHORIZED: {"description": "Credenciales no válidas", "model": HTTPExceptionModel},
                 }
                 )

async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    authenticate_user(form_data)
    access_token = create_access_token(data={"sub": form_data.username})
    return Token(access_token=access_token, token_type="bearer")

#######################################################################################################################################################################
# Endpoint para obtener las películas
#######################################################################################################################################################################

@router.get("/movies", 
            response_model=list[MovieSchema], 
            summary="Obtener las 10 mejores películas",
            responses={
                status.HTTP_200_OK: {"description": "Lista de las 10 películas mejor valoradas", "model": list[MovieSchema]},
                status.HTTP_401_UNAUTHORIZED: {"description": "Credenciales no válidas", "model": HTTPExceptionModel}
            }
)
def get_movies(current_user: UserSchema = Depends(get_validated_active_user)):
    """
    Recupera las 10 películas mejor valoradas de Redis, filtradas por el claim `cr` (content_rating) 
    y ordenadas por el campo 'tomatometer_rating' en orden descendente.
    """
    
    # Obtener el content_rating del usuario
    user_content_rating = current_user.content_rating

    # Recuperar las películas para el content_rating específico del usuario
    movies = redis.get(user_content_rating)
    
    # Decodificar las películas de JSON a una lista de diccionarios
    movies = json.loads(movies)
    
    # Ordenar y devolver las 10 mejores películas por tomatometer_rating
    sorted_movies = sorted(movies, key=lambda x: x['tomatometer_rating'], reverse=True)[:10]
    return sorted_movies



#######################################################################################################################################################################
# Endpoint para obtener el numero de claves de redis
#######################################################################################################################################################################

@router.get("/key-list-size", 
            summary="Devuelve el número de claves en Redis",
            responses={
                status.HTTP_200_OK: {"description": "Número de claves en Redis"},
                status.HTTP_401_UNAUTHORIZED: {"description": "Credenciales no válidas", "model": HTTPExceptionModel},
                }
                )

def get_key_list_size(apikey: str = Depends(apikey_security)):
    """
    Devuelve el número de claves almacenadas en Redis.
    Protegido mediante API Key.
    """

    validate_apikey(apikey)

    return len(redis.keys())
