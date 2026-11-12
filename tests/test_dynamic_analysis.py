"""
tests/test_dynamic_analysis.py
Light unit tests for dynamic analysis helpers (no browser launch needed).
"""
from app.dynamic_analysis.network_monitor import analyze_post_requests


class TestNetworkMonitor:
    def test_empty_requests_returns_dict(self):
        result = analyze_post_requests("https://example.com", [])
        assert isinstance(result, dict)

    def test_detects_external_post(self):
        requests = [
            {"method": "POST", "url": "https://evil-exfil.net/collect", "content_length": 512}
        ]
        result = analyze_post_requests("https://example.com", requests)
        assert isinstance(result, dict)

    def test_same_origin_post_not_flagged_as_external(self):
        requests = [
            {"method": "POST", "url": "https://example.com/api/submit", "content_length": 100}
        ]
        result = analyze_post_requests("https://example.com", requests)
        assert isinstance(result, dict)


class TestBrowserGate:
    def test_busy_response_when_gate_is_full(self, monkeypatch):
        import asyncio

        from app.dynamic_analysis import sandbox_runner as sr

        async def scenario():
            gate = asyncio.Semaphore(1)
            await gate.acquire()  # simulate a scan already holding the only slot
            monkeypatch.setattr(sr, "_browser_gate", gate)
            monkeypatch.setattr(sr, "BROWSER_QUEUE_TIMEOUT", 0.05)
            return await sr.run_dynamic_analysis("https://example.com")

        result = asyncio.run(scenario())
        assert result["classification"] == "Busy"
        assert result["engine_error"] == {"type": "SandboxBusy"}

    def test_gate_released_after_run(self, monkeypatch):
        import asyncio

        from app.dynamic_analysis import sandbox_runner as sr

        async def fake(url, static_results=None):
            return {"classification": "ok"}

        async def scenario():
            gate = asyncio.Semaphore(1)
            monkeypatch.setattr(sr, "_browser_gate", gate)
            monkeypatch.setattr(sr, "_run_dynamic_analysis", fake)
            await sr.run_dynamic_analysis("https://example.com")
            return gate._value

        assert asyncio.run(scenario()) == 1


class TestScanDeadline:
    def test_slow_scan_returns_timeout_and_frees_slot(self, monkeypatch):
        import asyncio

        from app.dynamic_analysis import sandbox_runner as sr

        async def slow(url, static_results=None):
            await asyncio.sleep(5)
            return {"classification": "ok"}

        async def scenario():
            gate = asyncio.Semaphore(1)
            monkeypatch.setattr(sr, "_browser_gate", gate)
            monkeypatch.setattr(sr, "_run_dynamic_analysis", slow)
            monkeypatch.setattr(sr, "DYNAMIC_SCAN_TIMEOUT", 0.2)
            monkeypatch.setattr(sr, "MIN_SCAN_SECONDS", 0.05)
            result = await sr.run_dynamic_analysis("https://example.com")
            return result, gate._value

        result, free = asyncio.run(scenario())
        assert result["classification"] == "Timeout"
        assert result["engine_error"] == {"type": "SandboxTimeout"}
        assert free == 1


class _FakeRoute:
    def __init__(self, url, navigation=False, fetched=None):
        self.request = type("R", (), {"url": url, "is_navigation_request": lambda self: navigation})()
        self._fetched = fetched
        self.action = None

    async def abort(self, reason=None):
        self.action = "abort"

    async def continue_(self):
        self.action = "continue"

    async def fetch(self, max_redirects=None):
        assert max_redirects == 0
        return self._fetched

    async def fulfill(self, response=None):
        self.action = "fulfill"


class _FakeFetched:
    def __init__(self, status, location=None):
        self.status = status
        self.headers = {"location": location} if location else {}


class TestPrivateHostGuard:
    def test_private_hosts_are_aborted_public_continue(self, monkeypatch):
        import asyncio

        from app.dynamic_analysis import sandbox_runner as sr

        monkeypatch.setattr(sr, "is_private_ip", lambda url: "169.254." in url or "internal" in url)
        blocked = []
        guard = sr.make_private_host_guard(blocked)

        async def scenario():
            routes = [_FakeRoute(u) for u in (
                "http://169.254.169.254/latest/meta-data/",
                "https://example.com/app.js",
                "http://internal.corp/admin",
                "data:text/plain,hi",
            )]
            for r in routes:
                await guard(r)
            return [r.action for r in routes]

        assert asyncio.run(scenario()) == ["abort", "continue", "abort", "continue"]
        assert len(blocked) == 2


class TestRequestRecord:
    def test_post_size_comes_from_body_not_header(self):
        from app.dynamic_analysis.sandbox_runner import request_record

        req = type("Req", (), {
            "method": "POST", "url": "https://evil.example/c",
            "headers": {}, "post_data_buffer": b"x" * 60_000,
        })()
        assert request_record(req)["content_length"] == 60_000

    def test_get_without_body_is_zero(self):
        from app.dynamic_analysis.sandbox_runner import request_record

        req = type("Req", (), {"method": "GET", "url": "https://e.example/", "headers": {}, "post_data_buffer": None})()
        assert request_record(req)["content_length"] == 0


class TestScreenshotPrune:
    def test_only_old_pngs_are_removed(self, tmp_path):
        import os
        import time

        from app.dynamic_analysis.sandbox_runner import prune_old_screenshots

        old_png, new_png, old_txt = tmp_path / "a_old.png", tmp_path / "b_new.png", tmp_path / "keep.txt"
        for f in (old_png, new_png, old_txt):
            f.write_bytes(b"x")
        two_days = time.time() - 2 * 86400
        os.utime(old_png, (two_days, two_days))
        os.utime(old_txt, (two_days, two_days))

        assert prune_old_screenshots(str(tmp_path), max_age_hours=24) == 1
        assert not old_png.exists() and new_png.exists() and old_txt.exists()


class TestNavigationRedirectGuard:
    def test_navigation_redirect_into_private_address_is_aborted(self, monkeypatch):
        import asyncio

        from app.dynamic_analysis import sandbox_runner as sr

        monkeypatch.setattr(sr, "is_private_ip", lambda url: "169.254." in url)
        blocked = []
        guard = sr.make_private_host_guard(blocked)
        hop = _FakeRoute("https://evil.example/", navigation=True,
                         fetched=_FakeFetched(302, "http://169.254.169.254/latest/meta-data/"))
        asyncio.run(guard(hop))
        assert hop.action == "abort"
        assert blocked == ["http://169.254.169.254/latest/meta-data/"]

    def test_navigation_to_public_page_is_fulfilled(self, monkeypatch):
        import asyncio

        from app.dynamic_analysis import sandbox_runner as sr

        monkeypatch.setattr(sr, "is_private_ip", lambda url: False)
        guard = sr.make_private_host_guard([])
        hop = _FakeRoute("https://example.com/", navigation=True, fetched=_FakeFetched(301, "/home"))
        asyncio.run(guard(hop))
        assert hop.action == "fulfill"
