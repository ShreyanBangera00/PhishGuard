"""
Unit tests for URL feature extraction and edge cases (PhishGuard Phase 8).
"""

import pytest
from src.features.url_features import extract_url_features, calculate_entropy


def test_standard_legitimate_url():
    url = "https://www.google.com/search?q=cybersecurity"
    feats = extract_url_features(url)
    
    assert feats['is_https'] == 1
    assert feats['has_ip'] == 0
    assert feats['has_shortener'] == 0
    assert feats['tld_risk'] == 0
    assert feats['url_length'] == len(url)


def test_ip_based_url():
    url = "http://192.168.1.100:8080/login.php"
    feats = extract_url_features(url)

    assert feats['has_ip'] == 1
    assert feats['is_https'] == 0
    assert feats['has_suspicious_words'] >= 1


def test_shortener_url():
    url = "http://bit.ly/secure-token"
    feats = extract_url_features(url)

    assert feats['has_shortener'] == 1
    assert feats['has_suspicious_words'] >= 1


def test_risky_tld_and_subdomains():
    url = "http://paypal.account-verification.login.tk/auth"
    feats = extract_url_features(url)

    assert feats['tld_risk'] == 1
    assert feats['num_subdomains'] >= 2
    assert feats['has_suspicious_words'] >= 1


def test_redirect_indicator():
    url = "http://trusted-site.com//redirect-to-malicious.com"
    feats = extract_url_features(url)

    assert feats['has_redirect'] == 1


def test_empty_and_invalid_inputs():
    empty_feats = extract_url_features("")
    assert empty_feats['url_length'] == 0
    assert empty_feats['has_ip'] == 0

    none_feats = extract_url_features(None)
    assert none_feats['url_length'] == 0


def test_very_long_url():
    long_url = "https://legit.com/" + "a" * 2500
    feats = extract_url_features(long_url)

    assert feats['url_length'] > 2500
    assert feats['path_length'] > 2500


def test_entropy_computation():
    low_entropy = calculate_entropy("aaaaaaa")
    high_entropy = calculate_entropy("a8b!z9$Qx@2#kL")

    assert low_entropy == 0.0
    assert high_entropy > 3.0
