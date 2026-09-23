"""
Integration tests for FastAPI endpoints (PhishGuard Phase 8).
Directly exercises endpoint handlers and request schemas for maximum reliability.
"""

import pytest
from fastapi import HTTPException
from src.api.main import (
    health_check,
    predict_url,
    analyze_email,
    get_live_feed,
    get_metrics,
    URLRequest,
    EmailRequest
)


def test_health_endpoint():
    data = health_check()
    assert data["status"] == "online"
    assert data["model_loaded"] is True


def test_predict_phishing_url():
    req = URLRequest(url="http://192.168.1.50:8080/secure/bank-login.html")
    data = predict_url(req)
    assert data["is_phishing"] is True
    assert data["label"] == "Phishing"
    assert data["confidence"] >= 50.0
    assert len(data["reasons"]) > 0


def test_predict_legitimate_url():
    req = URLRequest(url="https://www.google.com/search?q=cybersecurity")
    data = predict_url(req)
    assert data["is_phishing"] is False
    assert data["label"] == "Legitimate"
    assert data["confidence"] >= 50.0


def test_predict_empty_url_validation():
    req = URLRequest(url="   ")
    with pytest.raises(HTTPException) as exc_info:
        predict_url(req)
    assert exc_info.value.status_code == 400


def test_email_analysis_phishing():
    req = EmailRequest(
        sender="security@amazon-account-verify.xyz",
        claimed_org="Amazon",
        subject="URGENT: Your account has been suspended within 24 hours",
        body="Please login and confirm your password immediately."
    )
    data = analyze_email(req)
    assert data["risk_score"] >= 50
    assert data["is_suspicious"] is True


def test_live_feed_endpoint():
    data = get_live_feed(count=4)
    assert isinstance(data, list)
    assert len(data) <= 4
    if len(data) > 0:
        assert "url" in data[0]
        assert "label" in data[0]
        assert "confidence" in data[0]


def test_metrics_endpoint():
    data = get_metrics()
    assert "metrics" in data
    assert "Random Forest" in data["metrics"]


# ---------------------------------------------------------------------------
# New tests: SSRF guard (Issue #2) & TLS cert validation (Issue #1)
# ---------------------------------------------------------------------------

def test_ssrf_blocked_loopback():
    """SSRF guard must reject loopback addresses."""
    from src.scraper.page_analyzer import check_ssrf_safe
    is_safe, err = check_ssrf_safe("http://127.0.0.1/admin")
    assert is_safe is False
    assert err != ""


def test_ssrf_blocked_private_range():
    """SSRF guard must reject RFC-1918 private ranges."""
    from src.scraper.page_analyzer import check_ssrf_safe
    is_safe, err = check_ssrf_safe("http://192.168.1.1/")
    assert is_safe is False


def test_ssrf_allowed_public_domain():
    """SSRF guard must pass legitimate public domains."""
    from src.scraper.page_analyzer import check_ssrf_safe
    is_safe, err = check_ssrf_safe("https://www.google.com/")
    assert is_safe is True
    assert err == ""


def test_analyze_content_blocks_ssrf():
    """The /analyze-content endpoint must return HTTP 400 for SSRF-blocked URLs."""
    from src.api.main import analyze_content, URLRequest
    req = URLRequest(url="http://127.0.0.1/secret")
    with pytest.raises(HTTPException) as exc:
        analyze_content(req)
    assert exc.value.status_code == 400
    assert "SSRF" in exc.value.detail


def test_has_invalid_cert_field_present():
    """analyze_page must always return has_invalid_cert (even on empty/bad URL)."""
    from src.scraper.page_analyzer import analyze_page
    result = analyze_page("")
    assert "has_invalid_cert" in result
