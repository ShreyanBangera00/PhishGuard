"""
Dataset Preparation Script for PhishGuard.
Generates and processes a balanced 10,000-sample dataset (5,000 Legitimate, 5,000 Phishing)
combining known legitimate domain patterns and verified phishing attack vectors.
Extracts all 17 features and performs stratified 80/20 train-test splitting.

NOTE ON METHODOLOGY & LIMITATIONS:
This generator creates synthetic URLs incorporating explicit heuristics (IP addresses,
suspicious keywords, risky TLDs, subdomains, hyphens). Because the synthetic generation
rules align with the 17 extracted features, this dataset exhibits feature leakage that
makes the classification task artificially linearly/tree-separable (~100% accuracy).
Benchmark metrics on this data demonstrate generator separability rather than real-world
generalization. Evaluation against real-world corpora (e.g. PhishTank, OpenPhish) is
required for production deployment.
"""

import os
import random
import sys
import pandas as pd

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.features.url_features import extract_url_features
from src.models.ml_engine import train_test_split

# Top legitimate domains
LEGIT_DOMAINS = [
    'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'wikipedia.org', 'github.com', 'reddit.com', 'linkedin.com', 'netflix.com',
    'yahoo.com', 'instagram.com', 'twitter.com', 'facebook.com', 'adobe.com',
    'nytimes.com', 'bbc.co.uk', 'cnn.com', 'stackoverflow.com', 'medium.com',
    'spotify.com', 'ebay.com', 'dropbox.com', 'paypal.com', 'salesforce.com',
    'zoom.us', 'slack.com', 'twitch.tv', 'cloudflare.com', 'mozilla.org',
    'office.com', 'hulu.com', 'pinterest.com', 'quora.com', 'walmart.com',
    'target.com', 'etsy.com', 'imdb.com', 'espn.com', 'weather.com',
    'healthline.com', 'nih.gov', 'mit.edu', 'harvard.edu', 'stanford.edu'
]

LEGIT_PATHS = [
    '', '/', '/search', '/explore', '/docs/v2/api', '/watch?v=dQw4w9WgXcQ',
    '/products/electronics/deals', '/article/2026/03/technology-update',
    '/profile/settings', '/about/company', '/support/faq', '/pricing/enterprise',
    '/download/latest/installer.exe', '/resources/whitepapers', '/blog/machine-learning',
    '/feed/trending', '/category/news/world', '/user/dashboard/overview'
]

LEGIT_QUERIES = [
    '', '?q=cybersecurity+best+practices', '?ref=homepage&source=nav',
    '?category=all&page=2&sort=relevance', '?utm_source=newsletter&utm_medium=email',
    '?session_id=983427492&lang=en', '?view=compact&filter=active'
]

# Phishing generator vectors
SPOOFED_BRANDS = [
    'paypal', 'appleid', 'microsoft-login', 'amazon-support', 'wellsfargo-security',
    'chase-verify', 'bankofamerica-alert', 'netflix-billing', 'google-drive-share',
    'facebook-security', 'dhl-tracking', 'usps-redelivery', 'coinbase-auth',
    'metamask-validation', 'binance-trade', 'instagram-badge-verify'
]

RISKY_TLDS_LIST = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'loan', 'click', 'icu', 'vip']
SUSPICIOUS_PATHS = [
    '/login.php', '/verify-account.html', '/update-billing-information/',
    '/signin/auth?redirect=account', '/security-checkpoint/index.php',
    '/wallet/recovery-phrase.html', '/confirmation/payment-failed.aspx',
    '/authorize.cgi?session=', '/secure/portal/client-id/', '/dispute/center/'
]


def generate_legit_url(idx: int) -> str:
    """Generates realistic legitimate URL."""
    domain = random.choice(LEGIT_DOMAINS)
    subdomain = random.choice(['', 'www.', 'blog.', 'docs.', 'api.', 'support.']) if random.random() > 0.4 else ''
    path = random.choice(LEGIT_PATHS)
    query = random.choice(LEGIT_QUERIES) if random.random() > 0.5 else ''
    protocol = 'https://' if random.random() > 0.05 else 'http://'
    return f"{protocol}{subdomain}{domain}{path}{query}"


def generate_phishing_url(idx: int) -> str:
    """Generates realistic phishing URL simulating real phishing attacks."""
    attack_type = random.choice(['ip_address', 'typosquatting', 'subdomain_spoof', 'risky_tld', 'redirect_trick', 'shortener_abuse'])
    
    if attack_type == 'ip_address':
        ip = f"{random.randint(11, 219)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        port = f":{random.choice([8080, 8443, 8000, 3000])}" if random.random() > 0.6 else ""
        path = random.choice(SUSPICIOUS_PATHS)
        query = f"?verify={random.randint(10000, 99999)}&user=login"
        return f"http://{ip}{port}{path}{query}"
    
    elif attack_type == 'subdomain_spoof':
        brand = random.choice(SPOOFED_BRANDS)
        legit_target = random.choice(['paypal.com', 'apple.com', 'microsoft.com', 'google.com'])
        tld = random.choice(RISKY_TLDS_LIST)
        path = random.choice(SUSPICIOUS_PATHS)
        return f"http://{brand}.{legit_target}.account-verification-{random.randint(10, 99)}.{tld}{path}"
    
    elif attack_type == 'typosquatting':
        brand = random.choice(SPOOFED_BRANDS)
        hyphen_parts = f"{brand}-verification-{random.choice(['secure', 'portal', 'auth', 'update'])}"
        tld = random.choice(RISKY_TLDS_LIST)
        path = random.choice(SUSPICIOUS_PATHS)
        return f"http://{hyphen_parts}.{tld}{path}?session={random.randint(100000, 999999)}"

    elif attack_type == 'risky_tld':
        brand = random.choice(SPOOFED_BRANDS)
        tld = random.choice(RISKY_TLDS_LIST)
        path = random.choice(SUSPICIOUS_PATHS)
        return f"http://{brand}-security-update.{tld}{path}"

    elif attack_type == 'redirect_trick':
        brand = random.choice(SPOOFED_BRANDS)
        return f"http://{brand}-alert.com//redirect/index.php?url=http://malicious-collector.com/login"

    else:  # shortener abuse
        shortener = random.choice(['bit.ly', 'tinyurl.com', 'cutt.ly', 'rb.gy'])
        code = f"{random.choice(['sec', 'pay', 'act', 'auth'])}{random.randint(1000, 9999)}"
        return f"http://{shortener}/{code}"


def main():
    print("Generating balanced 10,000-sample dataset...")
    random.seed(42)
    
    data = []
    # 5,000 Legitimate URLs (label = 0)
    for i in range(5000):
        url = generate_legit_url(i)
        data.append({'url': url, 'label': 0})

    # 5,000 Phishing URLs (label = 1)
    for i in range(5000):
        url = generate_phishing_url(i)
        data.append({'url': url, 'label': 1})

    df = pd.DataFrame(data)
    # Deduplicate
    df = df.drop_duplicates(subset=['url']).reset_index(drop=True)
    print(f"Dataset after deduplication: {len(df)} samples ({df['label'].value_counts().to_dict()})")

    # Save raw/cleaned URLs
    base_dir = os.path.dirname(__file__)
    data_processed_dir = os.path.join(base_dir, 'processed')
    os.makedirs(data_processed_dir, exist_ok=True)
    
    cleaned_path = os.path.join(data_processed_dir, 'urls_cleaned.csv')
    df.to_csv(cleaned_path, index=False)
    print(f"Saved cleaned URLs to {cleaned_path}")

    # Extract features for all samples
    print("Extracting 17 features for all samples (this will take ~10-15 seconds)...")
    feature_list = []
    for url in df['url']:
        feats = extract_url_features(url)
        feature_list.append(feats)

    features_df = pd.DataFrame(feature_list)
    features_df['label'] = df['label'].values
    features_df['url'] = df['url'].values

    features_path = os.path.join(data_processed_dir, 'features.csv')
    features_df.to_csv(features_path, index=False)
    print(f"Saved extracted features dataset ({len(features_df)} rows) to {features_path}")

    # Verify stratified split
    X = features_df.drop(columns=['label', 'url'])
    y = features_df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    print(f"Train set: {len(X_train)} samples, Test set: {len(X_test)} samples")
    print(f"Phishing balance in Test: {y_test.value_counts().to_dict()}")
    print("Dataset generation complete!")


if __name__ == '__main__':
    main()
