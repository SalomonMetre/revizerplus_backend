from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from auth.routes import router as auth_router
from users.routes import router as user_router

app = FastAPI(
    title="Revizer Plus API",
    debug=settings.APP_DEBUG,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update with specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(user_router)

@app.get("/")
async def root():
    return {"message": "Welcome to Revizer Plus API"}
