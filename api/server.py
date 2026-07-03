import logging
from pydantic import BaseModel, HttpUrl
import uvicorn
from tools.db_manager import add_target, get_targets

logger = logging.getLogger("smp.api")

try:
    from fastapi import FastAPI, HTTPException
except ImportError:
    pass

app = FastAPI(title="SMP API", description="Security Management Platform Headless API", version="5.3")

class TargetCreate(BaseModel):
    url: HttpUrl
    company_name: str = ""
    submitted_to: str = ""

@app.post("/target")
def create_target(target: TargetCreate):
    """Add a new target to SMP."""
    success = add_target(str(target.url), target.company_name, target.submitted_to)
    if not success:
        raise HTTPException(status_code=400, detail="Target already exists or invalid.")
    return {"status": "success", "message": f"Target {target.url} added successfully."}

@app.get("/target")
def list_targets():
    """List all configured targets."""
    return {"targets": get_targets()}

def start_server(host="127.0.0.1", port=8000):
    logger.info(f"Starting FastAPI server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
