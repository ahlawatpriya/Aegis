"""FastAPI application for the Aegis web dashboard."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

_HERE = os.path.dirname(os.path.abspath(__file__))
_TEMPLATES_DIR = os.path.join(_HERE, "templates")
_STATIC_DIR = os.path.join(_HERE, "static")

templates = Jinja2Templates(directory=_TEMPLATES_DIR)
templates.env.auto_reload = True

_demo_mode = False


def is_demo_mode() -> bool:
    return _demo_mode


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


def create_app(demo: bool | None = None) -> FastAPI:
    global _demo_mode
    if demo is None:
        _demo_mode = os.environ.get("AEGIS_WEB_DEMO", "0") == "1"
    else:
        _demo_mode = demo

    app = FastAPI(
        title="Aegis — Supply Chain Risk Tracker",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    from aegis.web.routes.dashboard import router as dashboard_router
    from aegis.web.routes.sbom import router as sbom_router
    from aegis.web.routes.news import router as news_router
    from aegis.web.routes.match import router as match_router
    from aegis.web.routes.demo import router as demo_router
    from aegis.web.routes.chat import router as chat_router

    app.include_router(dashboard_router)
    app.include_router(sbom_router)
    app.include_router(news_router)
    app.include_router(match_router)
    app.include_router(demo_router)
    app.include_router(chat_router)

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        return templates.TemplateResponse(request, "base.html", {
            "title": "404 — Not Found",
            "content": "<h1 class='text-2xl font-bold text-red-500'>404 — Page not found</h1>",
            "demo_mode": is_demo_mode(),
        }, status_code=404)

    return app
