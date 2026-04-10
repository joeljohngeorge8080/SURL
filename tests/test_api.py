"""
tests/test_api.py
Integration tests for the FastAPI application.
These tests use httpx's AsyncClient against the real app instance.
No server needs to be running — the app is tested in-process.
"""
import pytest
from httpx import AsyncClient, ASGITransport


@pytest.fixture(scope="module")
def app():
    from app.main import app as fastapi_app
    return fastapi_app


@pytest.mark.asyncio
async def test_health_endpoint(app):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


@pytest.mark.asyncio
async def test_health_has_security_headers(app):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.asyncio
async def test_scan_rejects_empty_body(app):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/scan", json={})
    assert response.status_code == 422  # Pydantic validation error


@pytest.mark.asyncio
async def test_scan_rejects_url_over_2048_chars(app):
    long_url = "https://example.com/" + "a" * 2100
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/scan", json={"url": long_url})
    assert response.status_code == 422
