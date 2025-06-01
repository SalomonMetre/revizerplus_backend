from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import user

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://revizerplus.web.app/"],  # Replace with your frontend's origin
    allow_credentials=True,  # Allow cookies or auth headers if needed
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers (e.g., Content-Type, Authorization)
)

app.include_router(user.router)
