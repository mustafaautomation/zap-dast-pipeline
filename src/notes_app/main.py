"""Notes app: a small JSON API plus one HTML page, used as the target for ZAP scans.

``NOTES_INSECURE=1`` turns off the security headers and enables a search page that reflects
input without escaping. That mode exists only so CI can prove the scan and the gate catch
these problems; never deploy it.
"""

from __future__ import annotations

import html
import itertools
import os
import threading
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
PAGE_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'"
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cache-Control": "no-store",
}


class NoteIn(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    body: str = Field(default="", max_length=2000)


class Note(NoteIn):
    id: int


class NoteStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self._notes: dict[int, Note] = {}

    def add(self, data: NoteIn) -> Note:
        with self._lock:
            note = Note(id=next(self._ids), **data.model_dump())
            self._notes[note.id] = note
            return note

    def get(self, note_id: int) -> Note | None:
        with self._lock:
            return self._notes.get(note_id)

    def all(self) -> list[Note]:
        with self._lock:
            return list(self._notes.values())


def create_app(insecure: bool = False) -> FastAPI:
    # The interactive docs load scripts from a CDN, which the CSP would block; the
    # OpenAPI document itself stays available for the ZAP API scan.
    app = FastAPI(title="Notes", version="1.0.0", docs_url=None, redoc_url=None)
    store = NoteStore()
    store.add(NoteIn(title="Welcome", body="This note is seeded so the page is not empty."))

    if not insecure:

        @app.middleware("http")
        async def security_headers(
            request: Request, call_next: Callable[[Request], Awaitable[Response]]
        ) -> Response:
            response = await call_next(request)
            for name, value in SECURITY_HEADERS.items():
                response.headers.setdefault(name, value)
            is_page = response.headers.get("content-type", "").startswith("text/html")
            response.headers.setdefault("Content-Security-Policy", PAGE_CSP if is_page else API_CSP)
            return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/notes")
    def list_notes() -> list[Note]:
        return store.all()

    @app.post("/api/notes", status_code=201)
    def create_note(data: NoteIn) -> Note:
        return store.add(data)

    @app.get("/api/notes/{note_id}")
    def get_note(note_id: int) -> Note:
        note = store.get(note_id)
        if note is None:
            raise HTTPException(status_code=404, detail="note not found")
        return note

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        items = "".join(
            f"<li><strong>{html.escape(n.title)}</strong> {html.escape(n.body)}</li>" for n in store.all()
        )
        page = f"<!doctype html><html lang='en'><head><title>Notes</title></head><body><h1>Notes</h1><ul>{items}</ul></body></html>"
        response = HTMLResponse(page)
        response.set_cookie("session", "anonymous", httponly=True, secure=not insecure, samesite="strict")
        return response

    @app.get("/search", response_class=HTMLResponse)
    def search(q: str = "") -> HTMLResponse:
        shown = q if insecure else html.escape(q)  # insecure mode reflects raw input on purpose
        hits = [n for n in store.all() if q.lower() in n.title.lower()]
        page = (
            "<!doctype html><html lang='en'><head><title>Search</title></head><body>"
            f"<p>Results for {shown}: {len(hits)}</p></body></html>"
        )
        return HTMLResponse(page)

    return app


def run() -> None:
    import uvicorn

    insecure = os.environ.get("NOTES_INSECURE") == "1"
    uvicorn.run(
        create_app(insecure=insecure),
        host=os.environ.get("NOTES_HOST", "127.0.0.1"),
        port=int(os.environ.get("NOTES_PORT", "8000")),
        server_header=insecure,
    )
