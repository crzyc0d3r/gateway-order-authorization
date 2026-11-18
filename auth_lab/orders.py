"""Native orders service: caller identity plus resource ownership are both checked."""
import hmac

from fastapi import FastAPI, Header, HTTPException

from .auth import SERVICE_KEY
from .store import Orders


def create_app(store: Orders | None = None) -> FastAPI:
    app = FastAPI(title="Local orders service", version="1.0.0")
    app.state.orders = store if store is not None else Orders()

    def caller(x_user_id: str | None, x_service_token: str | None) -> int:
        if not hmac.compare_digest(x_service_token or "", SERVICE_KEY):
            raise HTTPException(401, "Gateway service identity required")
        if x_user_id not in {"1", "2"}:
            raise HTTPException(401, "Invalid caller")
        return int(x_user_id)

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "orders", "data": "synthetic"}

    @app.get("/orders")
    def list_orders(x_user_id: str | None = Header(None), x_service_token: str | None = Header(None)):
        return app.state.orders.list_for(caller(x_user_id, x_service_token))

    @app.get("/orders/{order_id}")
    def get_order(order_id: int, x_user_id: str | None = Header(None), x_service_token: str | None = Header(None)):
        result = app.state.orders.get_for(order_id, caller(x_user_id, x_service_token))
        if result is None:
            raise HTTPException(404, "Order not found")
        return result

    @app.post("/orders/{order_id}/reorder", status_code=201)
    def reorder(order_id: int, x_user_id: str | None = Header(None), x_service_token: str | None = Header(None)):
        result = app.state.orders.reorder_for(order_id, caller(x_user_id, x_service_token))
        if result is None:
            raise HTTPException(404, "Order not found")
        return result

    return app
