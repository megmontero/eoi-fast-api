from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from routers import movies

descripcion = 'Aplicación para mostrar peliculas.'


# Inicializar FastAPI
app = FastAPI(description=descripcion,
            version='0.0.1',
            title='Máster EOI - Movies API',
            contact={ "name": "Fernando Chicote",
                        "url": "https://github.com/fernandochicote",
                        "email": "fechicot@gmail.com"},
            license_info={
                        "name": "GPL-3.0",
                        "url": "https://www.gnu.org/licenses/gpl-3.0.html",
                    },
            openapi_tags = [
                                {
                                    "name": "movies",
                                    "description": "Operaciones pedidas en la actividad",
                                }
                        ]                   
)
app.include_router(movies.router)

@app.get("/", include_in_schema=False)
def redirigir():
    return RedirectResponse(url="/docs")
