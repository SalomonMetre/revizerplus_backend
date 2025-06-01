from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import user

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://revizerplus.web.app/"],      
    allow_credentials=True,  
    allow_methods=["*"],  
    allow_headers=["*"],  
)

app.include_router(user.router)
