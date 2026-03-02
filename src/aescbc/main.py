"""FastAPI application entrypoint."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from aescbc.api.routes import router as api_router

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "web" / "templates"
STATIC_DIR = BASE_DIR / "web" / "static"

app = FastAPI(title="AES-CBC Demo API", version="0.1.0")
app.include_router(api_router)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    css_path = STATIC_DIR / "css" / "styles.css"
    js_path = STATIC_DIR / "js" / "app.js"
    asset_version = f"{int(css_path.stat().st_mtime)}-{int(js_path.stat().st_mtime)}"

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "asset_version": asset_version,
        },
    )
