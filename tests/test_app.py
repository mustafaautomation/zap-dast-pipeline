import pytest
from fastapi.testclient import TestClient

from notes_app.main import API_CSP, PAGE_CSP, SECURITY_HEADERS, create_app


@pytest.fixture
def secure() -> TestClient:
    return TestClient(create_app())


@pytest.fixture
def insecure() -> TestClient:
    return TestClient(create_app(insecure=True))


@pytest.mark.parametrize(
    "path", ["/health", "/api/notes", "/api/notes/1", "/api/notes/999", "/", "/search?q=x", "/openapi.json"]
)
def test_security_headers_on_every_response(secure: TestClient, path: str) -> None:
    response = secure.get(path)
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, name
    assert "content-security-policy" in response.headers


def test_headers_also_on_validation_errors(secure: TestClient) -> None:
    response = secure.post("/api/notes", json={"title": ""})
    assert response.status_code == 422
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == API_CSP


def test_html_and_api_get_different_csp(secure: TestClient) -> None:
    assert secure.get("/").headers["content-security-policy"] == PAGE_CSP
    assert secure.get("/api/notes").headers["content-security-policy"] == API_CSP


def test_insecure_mode_has_no_security_headers(insecure: TestClient) -> None:
    response = insecure.get("/")
    assert "content-security-policy" not in response.headers
    assert "x-frame-options" not in response.headers


def test_search_escapes_input(secure: TestClient) -> None:
    body = secure.get("/search", params={"q": "<script>alert(1)</script>"}).text
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


def test_insecure_search_reflects_raw_input(insecure: TestClient) -> None:
    body = insecure.get("/search", params={"q": "<script>alert(1)</script>"}).text
    assert "<script>alert(1)</script>" in body


def test_index_escapes_stored_notes(secure: TestClient) -> None:
    secure.post("/api/notes", json={"title": "<img src=x onerror=alert(1)>", "body": "b"})
    body = secure.get("/").text
    assert "<img src=x" not in body
    assert "&lt;img src=x onerror=alert(1)&gt;" in body


def test_only_insecure_mode_sets_a_cookie(secure: TestClient, insecure: TestClient) -> None:
    assert "set-cookie" not in secure.get("/").headers
    cookie = insecure.get("/").headers["set-cookie"].lower()
    assert "httponly" not in cookie and "secure" not in cookie


def test_create_and_read_note(secure: TestClient) -> None:
    created = secure.post("/api/notes", json={"title": "Groceries", "body": "milk"})
    assert created.status_code == 201
    note_id = created.json()["id"]
    assert secure.get(f"/api/notes/{note_id}").json() == {"id": note_id, "title": "Groceries", "body": "milk"}


@pytest.mark.parametrize(
    "payload",
    [
        {"title": ""},
        {"title": "x" * 101},
        {"body": "no title"},
        {"title": "ok", "body": "x" * 2001},
        {"title": 5},
    ],
)
def test_note_validation(secure: TestClient, payload: dict[str, object]) -> None:
    assert secure.post("/api/notes", json=payload).status_code == 422


def test_missing_note_is_404(secure: TestClient) -> None:
    response = secure.get("/api/notes/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "note not found"}


def test_docs_disabled_but_openapi_available(secure: TestClient) -> None:
    assert secure.get("/docs").status_code == 404
    spec = secure.get("/openapi.json").json()
    assert "/api/notes" in spec["paths"]


def test_openapi_lists_only_json_routes(secure: TestClient) -> None:
    paths = set(secure.get("/openapi.json").json()["paths"])
    assert paths == {"/health", "/api/notes", "/api/notes/{note_id}"}


def test_index_links_to_search_so_the_spider_finds_it(secure: TestClient) -> None:
    assert "href='/search?q=welcome'" in secure.get("/").text
