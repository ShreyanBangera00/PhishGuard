"""
Explainability Module for PhishGuard (Rule-Based Feature Attribution).
Translates model feature importances and domain heuristics into human-understandable security insights
with directional impacts and actionable diagnostic messages.
"""

import numpy as np

# Human-readable rule explanations and advice
FEATURE_DESCRIPTIONS = {
    'has_ip': {
        'phish': "URL uses raw IP address instead of domain name (obfuscating ownership)",
        'legit': "URL uses standard domain name resolving"
    },
    'is_https': {
        'phish': "No HTTPS encryption — communication is insecure and unverified",
        'legit': "Uses valid HTTPS encryption protocol"
    },
    'has_suspicious_words': {
        'phish': "Contains suspicious credential-harvesting keyword(s) (e.g., login, verify, update)",
        'legit': "Standard path naming without deceptive keywords"
    },
    'has_shortener': {
        'phish': "Uses URL shortening service to conceal true destination",
        'legit': "Direct unshortened destination link"
    },
    'tld_risk': {
        'phish': "Uses high-risk, free, or frequently abused Top-Level Domain (TLD)",
        'legit': "Uses reputable standard Top-Level Domain (.com, .org, etc.)"
    },
    'has_redirect': {
        'phish': "Contains internal path redirect ('//') attempting to bypass security filters",
        'legit': "Normal hierarchical path structure"
    },
    'num_subdomains': {
        'phish': "Excessive subdomain chaining (often used to simulate brand domains)",
        'legit': "Standard domain structure"
    },
    'num_hyphens': {
        'phish': "Excessive hyphens in hostname/path (common in brand typosquatting)",
        'legit': "Natural domain hyphenation"
    },
    'num_dots': {
        'phish': "High dot count across domain and path",
        'legit': "Normal domain dot frequency"
    },
    'num_at': {
        'phish': "Contains '@' symbol (often used to trick browsers into ignoring preceding host)",
        'legit': "No credential redirection symbols"
    },
    'entropy': {
        'phish': "High character randomness / Shannon entropy (indicator of machine-generated obfuscation)",
        'legit': "Natural linguistic text entropy"
    },
    'url_length': {
        'phish': "Excessively long URL (>75 characters) often used to hide payload or tokens",
        'legit': "Normal concise URL length"
    },
    'hostname_length': {
        'phish': "Unusually long hostname",
        'legit': "Standard hostname length"
    },
    'special_char_ratio': {
        'phish': "Abnormally high proportion of special characters",
        'legit': "Standard character distribution"
    },
    'digit_ratio': {
        'phish': "High concentration of digits in URL",
        'legit': "Standard alphanumeric ratio"
    },
    'path_length': {
        'phish': "Extensively deep or obfuscated URL path",
        'legit': "Standard path depth"
    },
    'num_query_params': {
        'phish': "Complex tracking query parameters",
        'legit': "Standard query parameters"
    }
}


def explain_prediction(model, feature_names: list, feature_dict: dict, top_k: int = 5) -> list:
    """
    Computes rule-based feature attributions scaled by model feature importances for a single prediction
    and translates them into clear human-readable explanations.
    """
    importances = getattr(model, 'feature_importances_', None)
    if importances is None:
        importances = np.ones(len(feature_names)) / len(feature_names)

    attribution_values = []
    for feat_name, imp in zip(feature_names, importances):
        val = feature_dict.get(feat_name, 0)

        if feat_name == 'has_ip':
            impact = imp * 2.2 if val > 0 else -0.05
        elif feat_name == 'is_https':
            impact = -imp * 1.8 if val == 1 else imp * 1.8
        elif feat_name == 'has_suspicious_words':
            impact = min(val * 0.18, 0.45) if val > 0 else -0.04
        elif feat_name == 'tld_risk':
            impact = imp * 2.0 if val > 0 else -0.03
        elif feat_name == 'has_shortener':
            impact = imp * 1.9 if val > 0 else -0.02
        elif feat_name == 'has_redirect':
            impact = imp * 1.7 if val > 0 else 0.0
        elif feat_name == 'num_at':
            impact = imp * 2.0 if val > 0 else 0.0
        elif feat_name == 'num_subdomains':
            impact = 0.15 if val >= 2 else (-0.05 if val <= 1 else 0.02)
        elif feat_name == 'num_hyphens':
            impact = 0.14 if val >= 2 else (-0.04 if val == 0 else 0.02)
        elif feat_name == 'entropy':
            impact = 0.12 if val > 4.2 else (-0.06 if val < 3.5 else 0.01)
        elif feat_name == 'url_length':
            impact = 0.10 if val > 75 else (-0.05 if val < 40 else 0.01)
        else:
            impact = 0.02

        attribution_values.append(round(impact, 4))

    # Pair features with their attribution impact
    contributions = []
    for feat_name, attr_val in zip(feature_names, attribution_values):
        impact = float(attr_val)
        feat_val = feature_dict.get(feat_name, 0)
        
        desc_info = FEATURE_DESCRIPTIONS.get(feat_name, {
            'phish': f"Higher {feat_name} increases phishing risk",
            'legit': f"Normal {feat_name} indicates legitimate pattern"
        })

        if impact > 0.05:
            severity = 'critical' if impact > 0.15 else 'warning'
            badge = '🔴' if severity == 'critical' else '🟡'
            reason = desc_info['phish']
        elif impact < -0.03:
            severity = 'safe'
            badge = '🟢'
            reason = desc_info['legit']
        else:
            severity = 'neutral'
            badge = '⚪'
            reason = desc_info.get('legit', f"Normal {feat_name}")

        contributions.append({
            'feature': feat_name,
            'value': float(feat_val),
            'impact': impact,
            'reason': reason,
            'severity': severity,
            'badge': badge
        })

    # Sort by absolute impact descending
    contributions.sort(key=lambda x: abs(x['impact']), reverse=True)
    return contributions[:top_k]
