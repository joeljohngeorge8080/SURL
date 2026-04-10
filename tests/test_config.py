"""
tests/test_config.py
Tests for the application configuration and settings layer.
"""
from app.core.config import Settings


class TestSettings:
    def test_debug_is_false_by_default(self):
        s = Settings()
        assert s.DEBUG is False

    def test_rate_limit_default(self):
        s = Settings()
        assert s.RATE_LIMIT_PER_MINUTE == 30

    def test_cors_origin_list_returns_star_when_unset(self):
        s = Settings(CORS_ORIGINS="")
        assert s.cors_origin_list == ["*"]

    def test_cors_origin_list_parses_correctly(self):
        s = Settings(CORS_ORIGINS="https://app.example.com,https://admin.example.com")
        origins = s.cors_origin_list
        assert "https://app.example.com" in origins
        assert "https://admin.example.com" in origins
        assert len(origins) == 2

    def test_project_name_has_default(self):
        s = Settings()
        assert s.PROJECT_NAME != ""
