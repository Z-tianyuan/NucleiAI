"""NucleiAI Web Dashboard — FastAPI backend."""

from pathlib import Path
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="NucleiAI", version="0.1.0")

BASE_DIR = Path(__file__).resolve().parent.parent
static_dir = Path(__file__).resolve().parent / "static"
templates_dir = Path(__file__).resolve().parent / "templates"

templates = Jinja2Templates(directory=str(templates_dir))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Dashboard homepage."""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - AI增强漏洞管理平台",
    })
