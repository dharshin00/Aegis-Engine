import asyncio
from fastapi import FastAPI, Request, HTTPException, Header
from pydantic import BaseModel
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from db_listener import start_listener, stop_listener, get_recent_alerts, get_locked_users

# Load environment variables from .env file securely
load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup tasks
    print("Starting Project Aegis Intelligence Engine...")
    listener_task = asyncio.create_task(start_listener())
    yield
    # Shutdown tasks
    print("Shutting down Intelligence Engine...")
    await stop_listener()
    listener_task.cancel()

app = FastAPI(title="Project Aegis - Intelligence Engine", lifespan=lifespan)

# Mount the static directory to serve HTML/CSS/JS files
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except RuntimeError:
    print("[WARNING] Static directory not found. Creating it for the dashboard.")
    import os
    os.makedirs("static", exist_ok=True)
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def root():
    # Serve the React/HTML dashboard on the main page
    try:
        with open("static/index.html", "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        return "Dashboard HTML file not found."

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(req: LoginRequest):
    # Hardcoded admin credentials for this prototype
    if req.username == "admin" and req.password == "admin123":
        return {"token": "verified-admin-session"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/api/alerts")
async def get_alerts(authorization: str = Header(None)):
    if authorization != "Bearer verified-admin-session":
        raise HTTPException(status_code=401, detail="Unauthorized")
        
    # Return the latest alerts to the frontend javascript polling
    alerts = await get_recent_alerts()
    return {"alerts": alerts}

@app.get("/api/locked-users")
async def get_locked_users_api(authorization: str = Header(None)):
    if authorization != "Bearer verified-admin-session":
        raise HTTPException(status_code=401, detail="Unauthorized")
    users = await get_locked_users()
    return {"locked_users": users}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
