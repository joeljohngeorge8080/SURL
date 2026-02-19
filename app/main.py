from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.api.routes import router
import os
from app.core.exceptions import global_exception_handler




app = FastAPI()

# CORS (optional now, but keep for safety)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router)

# Get absolute path to html folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
html_path = os.path.join(BASE_DIR, "templates")

app.mount("/", StaticFiles(directory=html_path, html=True), name="static")

# Global Exception Handler
app.add_exception_handler(Exception, global_exception_handler)
