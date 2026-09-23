"""
Unit tests for Model inference, calibrated probabilities, and explainability (PhishGuard Phase 8).
"""

import os
import joblib
import pytest
from src.features.url_features import extract_url_features
from src.explainability.explainer import explain_prediction


@pytest.fixture
def model_bundle():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    model_path = os.path.join(base_dir, 'src', 'models', 'saved', 'production_model.pkl')
    assert os.path.exists(model_path), "production_model.pkl must exist before testing"
    return joblib.load(model_path)


def test_model_loads_and_has_features(model_bundle):
    assert 'model' in model_bundle
    assert 'metadata' in model_bundle
    feature_names = model_bundle['metadata']['feature_names']
    assert len(feature_names) == 17


def test_phishing_url_prediction(model_bundle):
    model = model_bundle['model']
    feature_names = model_bundle['metadata']['feature_names']

    phish_url = "http://192.168.1.50:8080/secure/bank-login.html?verify=account"
    feats = extract_url_features(phish_url)
    vector = [feats.get(k, 0) for k in feature_names]

    probs = model.predict_proba([vector])[0]
    p_phish = probs[1]

    assert p_phish > 0.60
    pred = model.predict([vector])[0]
    assert pred == 1


def test_legitimate_url_prediction(model_bundle):
    model = model_bundle['model']
    feature_names = model_bundle['metadata']['feature_names']

    legit_url = "https://www.google.com/search?q=cybersecurity"
    feats = extract_url_features(legit_url)
    vector = [feats.get(k, 0) for k in feature_names]

    probs = model.predict_proba([vector])[0]
    p_phish = probs[1]

    assert p_phish < 0.40
    pred = model.predict([vector])[0]
    assert pred == 0


def test_explainability_output_structure(model_bundle):
    model = model_bundle['model']
    feature_names = model_bundle['metadata']['feature_names']

    phish_url = "http://appleid.apple.com.manage-auth.tk/login.php"
    feats = extract_url_features(phish_url)

    reasons = explain_prediction(model, feature_names, feats, top_k=5)
    assert len(reasons) > 0
    for r in reasons:
        assert 'feature' in r
        assert 'impact' in r
        assert 'reason' in r
        assert 'badge' in r
        assert 'severity' in r
