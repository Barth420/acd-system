"""
app.py: the controller HTTP API (contract C, v1.1) on :8100. Errors are always {"error": "..."}.
CORS allows the main dashboard origins (http://localhost:8000 and http://127.0.0.1:8000).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from controller.core import Lab, LabError, make_direct_probe
from controller.dockerops import make_dockerops

CORS_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000"]


class ModeBody(BaseModel):
    mode: str


class EdgeBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    from_: str = Field(alias="from")
    to: str


class SeedBody(BaseModel):
    seed: Optional[int] = None
    time_scale: Optional[float] = None


class TrafficBody(BaseModel):
    rate_per_s: int = 5


def create_app(lab: Optional[Lab] = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        L()
        yield
        if app.state.lab is not None:
            app.state.lab.close()

    app = FastAPI(title="ACD lab controller", version="1.1", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])
    app.state.lab = lab

    def L() -> Lab:
        if app.state.lab is None:
            gw = os.getenv("GATEWAY_URL", "http://nginx:80")
            app.state.lab = Lab(os.getenv("CONTROL_STATE", "/control/state.json"), gw, make_dockerops(), make_direct_probe(gw))
        return app.state.lab

    @app.exception_handler(LabError)
    async def _lab_error(_: Request, e: LabError):
        return JSONResponse({"error": str(e)}, status_code=e.status)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, e: StarletteHTTPException):
        return JSONResponse({"error": str(e.detail)}, status_code=e.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, e: RequestValidationError):
        return JSONResponse({"error": "invalid request: " + "; ".join(f"{'.'.join(map(str, x['loc'][1:]))}: {x['msg']}" for x in e.errors())}, status_code=422)

    ui_dir = Path(__file__).resolve().parent / "ui"
    no_store = {"Cache-Control": "no-store"}        # NB: no X-Frame-Options / frame-ancestors header: the main dashboard embeds this page

    @app.get("/ui", include_in_schema=False)
    def ui_index():
        return FileResponse(ui_dir / "index.html", headers=no_store)

    @app.get("/ui/{name}", include_in_schema=False)
    def ui_asset(name: str):
        if name not in ("app.js", "style.css"):
            raise StarletteHTTPException(404, "not found")
        return FileResponse(ui_dir / name, headers=no_store)

    @app.get("/topology")
    def topology():
        return L().topology()

    @app.get("/state")
    def state():
        return L().snapshot()

    @app.post("/services/{name}/mode")
    def set_mode(name: str, body: ModeBody, x_actor: str = Header("unknown")):
        return L().set_mode(name, body.mode, x_actor)

    @app.post("/edges/cut")
    def cut(body: EdgeBody, x_actor: str = Header("unknown")):
        return L().cut_edge(body.from_, body.to, x_actor)

    @app.post("/edges/restore")
    def restore(body: EdgeBody, x_actor: str = Header("unknown")):
        return L().restore_edge(body.from_, body.to, x_actor)

    @app.post("/services/{name}/rotate-credentials")
    def rotate(name: str, x_actor: str = Header("unknown")):
        return L().rotate_credentials(name, x_actor)

    @app.post("/reset")
    def reset(x_actor: str = Header("unknown")):
        return L().reset(x_actor)

    @app.get("/health")
    def health():
        return L().health()

    @app.get("/actions")
    def actions():
        return list(L().actions)

    @app.post("/traffic/start")
    def traffic_start(body: TrafficBody, x_actor: str = Header("unknown")):
        L().traffic.start(body.rate_per_s)
        L().log(x_actor, "traffic_start", {"rate_per_s": body.rate_per_s}, "ok")
        return {"ok": True, "rate_per_s": body.rate_per_s}

    @app.post("/traffic/stop")
    def traffic_stop(x_actor: str = Header("unknown")):
        L().traffic.stop()
        L().log(x_actor, "traffic_stop", {}, "ok")
        return {"ok": True}

    return app


app = create_app()
