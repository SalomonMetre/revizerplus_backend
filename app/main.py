from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware import Middleware
from core.config import settings
from auth.routes import router as auth_router
from users.routes import router as user_router

# Configure middleware
middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,  # Set to False to allow wildcard origins
        allow_methods=["*"],
        allow_headers=["*"]
    )
]

app = FastAPI(
    title="Revizer Plus API",
    debug=settings.APP_DEBUG,
    docs_url="/docs",
    redoc_url="/redoc",
    middleware=middleware
)

# Include routers
app.include_router(auth_router)
app.include_router(user_router)

@app.get("/")
async def root():
    return {"message": "Welcome to Revizer Plus API"}
