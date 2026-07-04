import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

FRIGATE_URL = os.environ.get("FRIGATE_URL", "http://192.168.1.49:5000")

app = FastAPI(title="NVR Dashboard")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


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


@app.get("/health")
async def health():
    return {"status": "ok"}
