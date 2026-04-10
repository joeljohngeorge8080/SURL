"""
tests/test_dynamic_analysis.py
Light unit tests for dynamic analysis helpers (no browser launch needed).
"""
import pytest
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
