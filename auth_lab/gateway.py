"""Local authenticated gateway and explicit management-tool boundaries."""
import http.client
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPBearer
import httpx
from pydantic import BaseModel, ConfigDict, Field

from .auth import SERVICE_KEY, login, user_id
from .tooling import fetch_public_text, read_workspace, summarize, update_plan


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(max_length=30)
    password: str = Field(max_length=80)


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(max_length=80)


class SummaryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    value: str = Field(max_length=2048)


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = Field(pattern=r"^[a-z][a-z0-9-]{0,30}$")
    model: str = Field(min_length=1, max_length=80)
    api_key: str = Field(min_length=1, max_length=256)


def create_app(orders_transport=None) -> FastAPI:
    app = FastAPI(title="Gateway and local tooling boundary lab", version="1.0.0")
    app.state.settings = {}
    bearer = HTTPBearer(auto_error=False)
    workspace = Path(__file__).resolve().parent.parent / "examples" / "workspace"

    def authorize(request: Request) -> int:
        return user_id(request.headers.get("authorization"))

    def mutation_boundary(request: Request):
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise HTTPException(415, "application/json required")
        origin = request.headers.get("origin")
        if origin is not None and origin != "http://127.0.0.1:8766":
            raise HTTPException(403, "Origin not allowed")

    async def forward(request: Request, path: str, method: str = "GET"):
        caller = authorize(request)
        headers = {"X-User-Id": str(caller), "X-Service-Token": SERVICE_KEY}
        for name in ("traceparent", "accept-language"):
            if name in request.headers:
                headers[name] = request.headers[name]
        try:
            async with httpx.AsyncClient(base_url="http://127.0.0.1:8767", transport=orders_transport,
                                          timeout=5, trust_env=False) as client:
                response = await client.request(method, path, headers=headers)
        except httpx.HTTPError:
            raise HTTPException(502, "Orders service unavailable") from None
        if response.status_code not in {200, 201}:
            raise HTTPException(response.status_code, response.json().get("detail", "Orders request failed"))
        return response.json()

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "gateway", "data": "synthetic", "docs": "/docs"}

    @app.get("/demo")
    def demo():
        return {"login": "/auth/login", "synthetic_accounts": {"alice": "alice-demo", "bob": "bob-demo"},
                "walkthrough": ["Log in as bob", "GET /api/orders/3 returns his order",
                                "GET /api/orders/1 returns 404", "POST /api/orders/1/reorder returns 404"],
                "tooling": "Authenticated JSON-only management endpoints; update records a plan and never installs packages",
                "local_review": "http://127.0.0.1:8766/docs"}

    @app.post("/auth/login")
    def token(credentials: Credentials, request: Request):
        mutation_boundary(request)
        return {"access_token": login(credentials.username, credentials.password), "token_type": "bearer"}

    @app.get("/api/orders", dependencies=[Depends(bearer)])
    async def list_orders(request: Request):
        return await forward(request, "/orders")

    @app.get("/api/orders/{order_id}", dependencies=[Depends(bearer)])
    async def get_order(order_id: int, request: Request):
        return await forward(request, f"/orders/{order_id}")

    @app.post("/api/orders/{order_id}/reorder", status_code=201, dependencies=[Depends(bearer)])
    async def reorder(order_id: int, request: Request):
        mutation_boundary(request)
        return await forward(request, f"/orders/{order_id}/reorder", "POST")

    @app.post("/api/update", dependencies=[Depends(bearer)])
    async def update(request: Request):
        authorize(request)
        mutation_boundary(request)
        try:
            target = Target.model_validate(await request.json())
            return update_plan(target.target)
        except (ValueError, TypeError):
            raise HTTPException(400, "A valid version-only target is required") from None

    @app.post("/api/settings", dependencies=[Depends(bearer)])
    async def settings(request: Request):
        caller = authorize(request)
        mutation_boundary(request)
        try:
            values = Settings.model_validate(await request.json())
        except (ValueError, TypeError):
            raise HTTPException(400, "Invalid provider settings") from None
        app.state.settings[caller] = values.model_dump()
        return {"provider": values.provider, "model": values.model, "api_key": "[redacted]"}

    @app.post("/api/summarize", dependencies=[Depends(bearer)])
    def summary(values: SummaryInput, request: Request):
        authorize(request)
        mutation_boundary(request)
        try:
            if values.kind == "file":
                text = read_workspace(workspace, values.value)
            elif values.kind == "url":
                text = fetch_public_text(values.value)
            else:
                raise ValueError("Unknown source kind")
            return summarize(text)
        except (ValueError, OSError, UnicodeError, http.client.HTTPException):
            raise HTTPException(400, "Source unavailable or outside the permitted budget") from None

    return app
