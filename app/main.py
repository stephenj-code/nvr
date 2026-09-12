import os
import json
import base64
import logging
import asyncio

import httpx
import websockets
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

FRIGATE_URL = os.environ.get("FRIGATE_URL", "http://192.168.1.49:5000")
APP_URL = os.environ.get("APP_URL", "https://nvr.project-solomon.ai")
KEYCLOAK_ISSUER = os.environ.get("KEYCLOAK_ISSUER", "https://keycloak.project-solomon.ai/realms/solomon")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "infra-apps")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET")
SESSION_SECRET = os.environ.get("SESSION_SECRET")
REQUIRED_ROLE = "nvr-access"

if not CLIENT_SECRET:
    raise RuntimeError("OIDC_CLIENT_SECRET is required")
if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is required")

logger = logging.getLogger("nvr")


def get_user(request: Request) -> dict | None:
    return request.session.get("user")


def get_roles(request: Request) -> list:
    return request.session.get("roles", [])


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        public_paths = ("/health", "/auth/", "/static/", "/ws/")
        if any(request.url.path.startswith(p) for p in public_paths):
            return await call_next(request)

        user = get_user(request)
        if not user:
            request.session["return_to"] = str(request.url.path)
            return RedirectResponse(url="/auth/login")

        roles = get_roles(request)
        if REQUIRED_ROLE not in roles:
            return HTMLResponse(
                "<html><body style='font-family:sans-serif;text-align:center;padding:4rem'>"
                "<h2>Access Denied</h2>"
                f"<p>Your account does not have the <strong>{REQUIRED_ROLE}</strong> role.</p>"
                "<a href='/auth/logout'>Sign out</a></body></html>",
                status_code=403,
            )

        return await call_next(request)


app = FastAPI(title="NVR Dashboard")
app.add_middleware(AuthMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, session_cookie="nvr-session",
                   max_age=8 * 60 * 60, https_only=True, same_site="lax")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ── OIDC setup ───────────────────────────────────────────────────────────────

oauth = OAuth()
oauth.register(
    name="keycloak",
    server_metadata_url=f"{KEYCLOAK_ISSUER}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    client_kwargs={"scope": "openid email profile"},
)


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification (token is trusted — just came from Keycloak)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)  # pad base64
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


# ── Auth routes (public) ────────────────────────────────────────────────────

@app.get("/auth/login")
async def login(request: Request):
    redirect_uri = f"{APP_URL}/auth/callback"
    return await oauth.keycloak.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback")
async def callback(request: Request):
    try:
        token = await oauth.keycloak.authorize_access_token(request)
        userinfo = token.get("userinfo", {})
        access_claims = decode_jwt_payload(token.get("access_token", ""))
        client_roles = access_claims.get("resource_access", {}).get(CLIENT_ID, {}).get("roles", [])

        request.session["user"] = {
            "name": userinfo.get("name", ""),
            "email": userinfo.get("email", ""),
            "sub": userinfo.get("sub", ""),
        }
        request.session["roles"] = client_roles
        request.session["id_token"] = token.get("id_token", "")

        if REQUIRED_ROLE not in client_roles:
            logger.warning("Access denied — missing role %s for %s", REQUIRED_ROLE, userinfo.get("email"))
            return HTMLResponse(
                "<html><body style='font-family:sans-serif;text-align:center;padding:4rem'>"
                "<h2>Access Denied</h2>"
                f"<p>Your account does not have the <strong>{REQUIRED_ROLE}</strong> role.</p>"
                "<a href='/auth/logout'>Sign out</a></body></html>",
                status_code=403,
            )

        logger.info("User authenticated: %s roles=%s", userinfo.get("email"), client_roles)
        return_to = request.session.pop("return_to", "/")
        return RedirectResponse(url=return_to)
    except Exception as e:
        logger.error("OIDC callback error: %s", e)
        return RedirectResponse(url="/auth/login")


@app.get("/auth/logout")
async def logout(request: Request):
    email = request.session.get("user", {}).get("email", "")
    request.session.clear()
    logger.info("User logged out: %s", email)
    response = RedirectResponse(url="/auth/login")
    # Explicitly expire the session cookie so the browser discards it
    response.delete_cookie("nvr-session", path="/", secure=True, httponly=True, samesite="lax")
    return response


@app.get("/auth/me")
async def me(request: Request):
    user = get_user(request)
    if not user:
        return JSONResponse({"authenticated": False}, status_code=401)
    return {"authenticated": True, "user": user}


# ── App routes (protected by middleware) ─────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/events")
async def events(limit: int = 20):
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{FRIGATE_URL}/api/events",
            params={"limit": limit},
            timeout=10.0,
        )
        return JSONResponse(content=resp.json(), status_code=resp.status_code)


@app.get("/api/stats")
async def stats():
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{FRIGATE_URL}/api/stats", timeout=10.0)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)


@app.get("/stream/{camera_name}")
async def stream(camera_name: str):
    async def proxy_stream():
        async with httpx.AsyncClient() as client:
            async with client.stream(
                "GET",
                f"{FRIGATE_URL}/api/{camera_name}/latest.jpg",
                timeout=None,
            ) as resp:
                async for chunk in resp.aiter_bytes():
                    yield chunk

    return StreamingResponse(proxy_stream(), media_type="image/jpeg")


GO2RTC_URL = FRIGATE_URL.replace(":5000", ":1984")


@app.get("/live/{stream_name}")
async def live_frame(stream_name: str, width: int = 1280):
    """Proxy go2rtc JPEG frame, downscaled for fast delivery."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{GO2RTC_URL}/api/frame.jpeg?src={stream_name}&width={width}",
            timeout=10.0,
        )
        return StreamingResponse(
            iter([resp.content]),
            media_type="image/jpeg",
            headers={"Cache-Control": "no-cache"},
        )


@app.get("/mjpeg/{camera_name}")
async def mjpeg(camera_name: str):
    async def proxy_mjpeg():
        async with httpx.AsyncClient() as client:
            async with client.stream(
                "GET",
                f"{FRIGATE_URL}/api/{camera_name}",
                timeout=None,
            ) as resp:
                async for chunk in resp.aiter_bytes():
                    yield chunk

    return StreamingResponse(
        proxy_mjpeg(),
        media_type="multipart/x-mixed-replace; boundary=frame",
    )


@app.api_route(
    "/frigate/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE"],
)
async def frigate_proxy(request: Request, path: str):
    async with httpx.AsyncClient() as client:
        url = f"{FRIGATE_URL}/{path}"
        resp = await client.request(
            method=request.method,
            url=url,
            params=dict(request.query_params),
            headers={
                k: v
                for k, v in request.headers.items()
                if k.lower() not in ("host", "connection")
            },
            content=await request.body(),
            timeout=30.0,
        )
        return StreamingResponse(
            iter([resp.content]),
            status_code=resp.status_code,
            headers=dict(resp.headers),
            media_type=resp.headers.get("content-type"),
        )


@app.websocket("/ws/go2rtc")
async def go2rtc_ws_proxy(ws: WebSocket, src: str = "front_door"):
    """Proxy WebSocket connection to go2rtc for MSE live streaming."""
    await ws.accept()
    go2rtc_ws_url = f"ws://{GO2RTC_URL.split('://')[-1]}/api/ws?src={src}"
    try:
        async with websockets.connect(go2rtc_ws_url) as go2rtc:
            async def browser_to_go2rtc():
                try:
                    while True:
                        msg = await ws.receive()
                        if "text" in msg:
                            await go2rtc.send(msg["text"])
                        elif "bytes" in msg:
                            await go2rtc.send(msg["bytes"])
                except Exception:
                    pass

            async def go2rtc_to_browser():
                try:
                    async for msg in go2rtc:
                        if isinstance(msg, bytes):
                            await ws.send_bytes(msg)
                        else:
                            await ws.send_text(msg)
                except Exception:
                    pass

            done, pending = await asyncio.wait(
                [asyncio.create_task(browser_to_go2rtc()),
                 asyncio.create_task(go2rtc_to_browser())],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
    except Exception as e:
        logger.warning("go2rtc WebSocket proxy error: %s", e)
    finally:
        try:
            await ws.close()
        except Exception:
            pass


@app.get("/health")
async def health():
    return {"status": "ok"}
