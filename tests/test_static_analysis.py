"""
tests/test_static_analysis.py
Unit tests for the static analysis pipeline.
"""
import pytest
from static_analysis.url_normalizer import normalize_url, validate_domain
from static_analysis.lexical_analyzer import lexical_analysis
from static_analysis.protocol_check import http_checker


class TestUrlNormalizer:
    def test_adds_https_scheme(self):
        result = normalize_url("google.com")
        assert result.startswith("https://")

    def test_preserves_existing_scheme(self):
        result = normalize_url("http://example.com")
        assert result == "http://example.com"

    def test_strips_whitespace(self):
        result = normalize_url("  https://example.com  ")
        assert "example.com" in result

    def test_valid_domain(self):
        assert validate_domain("example.com") is True

    def test_invalid_domain_empty(self):
        assert validate_domain("") is False

    def test_invalid_domain_spaces(self):
        assert validate_domain("not a domain") is False


class TestLexicalAnalyzer:
    def test_returns_dict(self):
        result = lexical_analysis("https://paypa1-secure-login.com/account")
        assert isinstance(result, dict)

    def test_detects_suspicious_keywords(self):
        result = lexical_analysis("https://secure-login-verify.com")
        assert result.get("suspicious_keywords") is True

    def test_clean_url_no_flags(self):
        result = lexical_analysis("https://google.com")
        assert isinstance(result, dict)
        assert result.get("ip_based_url") is False


class TestProtocolCheck:
    def test_https_is_secure(self):
        result = http_checker("https://example.com")
        assert isinstance(result, dict)
        assert result.get("uses_https") is True

    def test_http_is_not_secure(self):
        result = http_checker("http://example.com")
        assert isinstance(result, dict)
        assert result.get("uses_https") is False
