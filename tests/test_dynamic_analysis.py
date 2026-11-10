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
