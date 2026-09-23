// PhishGuard Frontend Controller
document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const tabs = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  const urlInput = document.getElementById('url-input');
  const btnScan = document.getElementById('btn-scan');
  const btnDeepScan = document.getElementById('btn-deep-scan');
  const scanLoader = document.getElementById('scan-loader');
  const resultSection = document.getElementById('result-section');
  const sampleChips = document.querySelectorAll('.sample-chip');

  // Verdict Elements
  const verdictBanner = document.getElementById('verdict-banner');
  const verdictIcon = document.getElementById('verdict-icon');
  const verdictTag = document.getElementById('verdict-tag');
  const verdictTitle = document.getElementById('verdict-title');
  const targetUrlDisplay = document.getElementById('target-url-display');
  const confidenceValue = document.getElementById('confidence-value');
  const riskBarFill = document.getElementById('risk-bar-fill');
  const riskCaption = document.getElementById('risk-caption');
  const reasonsList = document.getElementById('reasons-list');
  const featureChips = document.getElementById('feature-chips');
  const pageScanDetails = document.getElementById('page-scan-details');
  const pageSignals = document.getElementById('page-signals');

  // Email Elements
  const emailSender = document.getElementById('email-sender');
  const emailClaimedOrg = document.getElementById('email-claimed-org');
  const emailSubject = document.getElementById('email-subject');
  const emailBody = document.getElementById('email-body');
  const btnScanEmail = document.getElementById('btn-scan-email');
  const btnTestPhishEmail = document.getElementById('btn-test-phish-email');
  const emailResult = document.getElementById('email-result');

  // Feed & Metrics references removed
  
  // ─── 1. Tab Switching ───
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetTab = document.getElementById(btn.dataset.tab);
      if (targetTab) {
        targetTab.classList.add('active');
      }
    });
  });

  // ─── 3. Scan Triggers ───
  btnScan.addEventListener('click', () => triggerScan(false));
  btnDeepScan.addEventListener('click', () => triggerScan(true));

  urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') triggerScan(false);
  });

  async function triggerScan(isDeep = false) {
    const url = urlInput.value.trim();
    if (!url) {
      alert('Please enter a URL to analyze.');
      return;
    }

    scanLoader.classList.remove('hidden');
    resultSection.classList.add('hidden');

    try {
      const endpoint = isDeep ? '/api/analyze-content' : '/api/predict';
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Analysis failed');
      }

      const data = await response.json();
      renderVerdict(data, isDeep);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      scanLoader.classList.add('hidden');
    }
  }

  // ─── 4. Render Verdict ───
  function renderVerdict(data, isDeep = false) {
    resultSection.classList.remove('hidden');

    const isPhish = data.is_phishing;
    targetUrlDisplay.textContent = data.url;
    confidenceValue.textContent = `${data.confidence}%`;
    riskCaption.textContent = `Risk Score: ${data.risk_score} / 100`;
    riskBarFill.style.width = `${Math.min(Math.max(data.risk_score, 3), 100)}%`;

    if (isPhish) {
      verdictBanner.className = 'verdict-banner danger';
      verdictIcon.innerHTML = '<svg viewBox="0 0 24 24"><path d="M18 6L6 18M6 6l12 12"/></svg>';
      verdictTag.textContent = 'THREAT DETECTED';
      verdictTitle.textContent = 'Phishing Attack Detected';
    } else {
      verdictBanner.className = 'verdict-banner safe';
      verdictIcon.innerHTML = '<svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>';
      verdictTag.textContent = 'SAFE';
      verdictTitle.textContent = 'URL Appears Legitimate';
    }

    // Render Feature Attribution Reasons
    reasonsList.innerHTML = '';
    (data.reasons || []).forEach(r => {
      const item = document.createElement('div');
      item.className = `reason-item ${r.severity || 'neutral'}`;

      const sign = r.impact > 0 ? '+' : '';
      item.innerHTML = `
        <div class="reason-left">
          <span class="reason-dot"></span>
          <span>${r.reason}</span>
        </div>
        <span class="reason-impact">${sign}${r.impact.toFixed(3)}</span>
      `;
      reasonsList.appendChild(item);
    });

    // Render Extracted Features
    featureChips.innerHTML = '';
    const feats = data.features || {};
    const displayKeys = [
      'url_length', 'hostname_length', 'num_dots', 'num_hyphens',
      'has_ip', 'is_https', 'has_shortener', 'num_subdomains',
      'has_suspicious_words', 'entropy', 'tld_risk', 'has_redirect'
    ];

    displayKeys.forEach(k => {
      if (feats[k] !== undefined) {
        const chip = document.createElement('div');
        chip.className = 'feat-chip';
        const label = k.replace(/_/g, ' ');
        const val = typeof feats[k] === 'number'
          ? (Number.isInteger(feats[k]) ? feats[k] : feats[k].toFixed(3))
          : feats[k];
        chip.innerHTML = `
          <span class="feat-label">${label}</span>
          <span class="feat-val">${val}</span>
        `;
        featureChips.appendChild(chip);
      }
    });

    // Threat Intel badge (if available)
    if (data.threat_intel && data.threat_intel.google_safe_browsing) {
      const gsb = data.threat_intel.google_safe_browsing;
      const existingBadge = resultSection.querySelector('.threat-intel-badge');
      if (existingBadge) existingBadge.remove();

      const badge = document.createElement('div');
      if (!gsb.available) {
        badge.className = 'threat-intel-badge unavailable';
        badge.textContent = 'Google Safe Browsing: Not configured';
      } else if (gsb.is_threat) {
        badge.className = 'threat-intel-badge active';
        badge.textContent = `Google Safe Browsing: Flagged (${(gsb.threat_types || []).join(', ')})`;
      } else {
        badge.className = 'threat-intel-badge clear';
        badge.textContent = 'Google Safe Browsing: No threats found';
      }

      const verdictRight = document.querySelector('.verdict-right');
      if (verdictRight) verdictRight.appendChild(badge);
    }

    // Network & Domain Intel
    const networkIntelDetails = document.getElementById('network-intel-details');
    const networkSignals = document.getElementById('network-signals');
    if (data.network_intel && (data.network_intel.ip_address || data.network_intel.registrar)) {
      networkIntelDetails.classList.remove('hidden');
      const ni = data.network_intel;
      
      const ipText = ni.ip_address ? `${ni.ip_address} (${ni.country || 'Unknown'}, ${ni.asn_org || 'Unknown ISP'})` : 'Resolution failed';
      const ageText = ni.domain_age_days ? `${ni.domain_age_days} days old (Created: ${ni.creation_date})` : 'Unknown';
      const tlsText = ni.tls_issuer ? `Issued by ${ni.tls_issuer} (Valid for ${ni.tls_valid_days} days)` : 'No valid certificate';

      networkSignals.innerHTML = `
        <div class="page-signal-row"><span>Main Domain</span><strong>${ni.domain || 'N/A'}</strong></div>
        <div class="page-signal-row"><span>DNS A Record</span><strong>${ipText}</strong></div>
        <div class="page-signal-row"><span>Registrar</span><strong>${ni.registrar || 'Hidden / Unknown'}</strong></div>
        <div class="page-signal-row"><span>Domain Age</span><strong>${ageText}</strong></div>
        <div class="page-signal-row"><span>TLS Certificate</span><strong>${tlsText}</strong></div>
      `;
    } else {
      if (networkIntelDetails) networkIntelDetails.classList.add('hidden');
    }

    // Deep Page Signals
    if (isDeep && data.page_analysis) {
      pageScanDetails.classList.remove('hidden');
      const pa = data.page_analysis;
      pageSignals.innerHTML = `
        <div class="page-signal-row"><span>Landing Page Status</span><strong>${pa.accessible ? 'Accessible (200 OK)' : (pa.error || 'Unreachable')}</strong></div>
        <div class="page-signal-row"><span>TLS / SSL Certificate</span><strong>${pa.has_invalid_cert ? 'Invalid / Untrusted' : 'Valid'}</strong></div>
        <div class="page-signal-row"><span>Page Title</span><strong>${pa.page_title || 'N/A'}</strong></div>
        <div class="page-signal-row"><span>Login Form Present</span><strong>${pa.has_login_form ? 'Yes — credential input detected' : 'No'}</strong></div>
        <div class="page-signal-row"><span>External Asset Ratio</span><strong>${(pa.external_resource_ratio * 100).toFixed(1)}%</strong></div>
        <div class="page-signal-row"><span>Brand Impersonation</span><strong>${pa.has_brand_mismatch ? `Detected (${pa.detected_brand})` : 'None detected'}</strong></div>
      `;
    } else {
      pageScanDetails.classList.add('hidden');
    }

    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ─── 5. Email Inspector ───
  btnTestPhishEmail.addEventListener('click', () => {
    emailSender.value = 'security-update@paypal-auth-center.xyz';
    emailClaimedOrg.value = 'PayPal';
    emailSubject.value = 'URGENT: Suspicious activity detected on your PayPal account!';
    emailBody.value = `Dear Customer,

We detected unauthorized sign-in attempts to your account. Your access has been restricted immediately.
You must verify your billing credentials within 24 hours or your account will be permanently suspended.

Click here to verify now: http://paypal-resolution-center.xyz/update-account?session=89324

Please provide your login password and credit card details to confirm ownership.
Thank you,
PayPal Security Department`;
  });

  btnScanEmail.addEventListener('click', async () => {
    const payload = {
      sender: emailSender.value.trim(),
      claimed_org: emailClaimedOrg.value.trim(),
      subject: emailSubject.value.trim(),
      body: emailBody.value.trim()
    };

    if (!payload.body && !payload.subject) {
      alert('Please enter an email subject or body.');
      return;
    }

    try {
      const resp = await fetch('/api/analyze-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await resp.json();

      emailResult.classList.remove('hidden');
      const isSusp = data.is_suspicious;
      emailResult.className = `email-result-box ${isSusp ? 'danger' : 'safe'}`;

      let reasonsHtml = (data.reasons || []).map(r => `
        <div class="page-signal-row">
          <span><strong>${r.rule}</strong></span>
          <span>${r.detail}</span>
        </div>
      `).join('');

      emailResult.innerHTML = `
        <h4>${isSusp ? 'High-Risk Phishing Email Detected' : 'Low Threat — Normal Communication'}</h4>
        <p style="margin-bottom: 12px; font-size: 13px; color: var(--text-secondary);">Risk Score: <strong>${data.risk_score}/100</strong></p>
        <div>${reasonsHtml}</div>
      `;
    } catch (e) {
      alert('Error analyzing email: ' + e.message);
    }
  });


});
