from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY

import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="QMsg - Quantum-Safe Messaging",
    description="A quantum-safe messaging platform using Kyber KEM encryption",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite development server
        "http://localhost:8081",  # Vite development server alternative
        "http://127.0.0.1:5173",  # Vite development server
        "http://localhost:4173",  # Vite preview
        "http://127.0.0.1:4173",  # Vite preview
        "http://localhost:3000",  # React development (if needed)
        os.getenv("FRONTEND_URL", "http://localhost:5173")  # From .env file
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=[
        "Content-Type",
        "Authorization",
        "Access-Control-Allow-Headers",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials"
    ],
    expose_headers=["*"]  # Expose all headers to the frontend
)

# Session middleware for managing user sessions
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "your-secret-key-here")
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()}
    )

@app.get("/api/v1/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

# Import and include routers
from app.api.v1.endpoints import auth, users, messages

app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(messages.router, prefix="/api/v1/messages", tags=["Messages"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 