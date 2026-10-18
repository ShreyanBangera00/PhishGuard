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
        <div class="page-signal-row" style="padding: 6px 0; border-bottom: 1px dashed rgba(0,0,0,0.08);">
          <span><strong>${r.badge || ''} ${r.rule}</strong></span>
          <span style="font-size: 12.5px; text-align: right; max-width: 65%;">${r.detail}</span>
        </div>
      `).join('');

      const FEATURE_LABELS = {
        sender_domain_mismatch: 'Sender Domain Spoofing',
        cred_request_score: 'Credential Solicitation (Zone-Scaled)',
        html_form_present: 'Malicious URL / Payload Structure',
        urgency_score: 'Psychological Urgency (Zone-Scaled)',
        poor_grammar_score: 'Generic Salutation & Spam Phrases',
        num_links: 'Hyperlink Volume & Risk Density'
      };

      const breakdown = data.breakdown || [];
      const mc = data.model_comparison || (data.features && data.features.model_comparison) || null;

      const propRawSum = breakdown.reduce((s, b) => s + b.contribution, 0);
      const synergyBonus = mc && mc.proposed_ahmfa ? mc.proposed_ahmfa.synergy_bonus : 0;
      const propShStar = mc && mc.proposed_ahmfa ? mc.proposed_ahmfa.S_H_star : Math.min(100, propRawSum);
      const baseSh = mc && mc.base_paper ? mc.base_paper.S_H : 0;

      let comparisonCardsHtml = '';
      if (mc && mc.base_paper && mc.proposed_ahmfa) {
        const bp = mc.base_paper;
        const pa = mc.proposed_ahmfa;
        const legacyScore = mc.legacy_v1_score !== undefined ? mc.legacy_v1_score : 70;

        comparisonCardsHtml = `
          <div style="margin-top: 16px; display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px;">
            <div style="background: rgba(255,255,255,0.85); border: 1px solid #d1d5db; border-radius: 8px; padding: 12px;">
              <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: #6b7280; letter-spacing: 0.5px;">
                BASELINE &mdash; JADHAV & CHANDRE (2025) PAPER
              </div>
              <div style="font-size: 18px; font-weight: 800; color: #374151; margin: 4px 0;">
                ${bp.final_score} / 100
                <span style="font-size: 11px; font-weight: 500; color: #6b7280;">(Legacy v1: ${legacyScore}/100)</span>
              </div>
              <div style="font-family: monospace; font-size: 11.5px; color: #4b5563; line-height: 1.5;">
                S<sub>H</sub> = &Sigma;(&alpha;<sub>i</sub> &middot; h<sub>i</sub>) = <strong>${bp.S_H}</strong> (Binary h<sub>i</sub> &isin; {0,1})<br>
                S<sub>final</sub> = 0.50&middot;(${bp.S_H}) + 0.50&middot;(${bp.P_ML}) = <strong>${bp.final_score}</strong>
              </div>
              <div style="margin-top: 6px; font-size: 11px; color: #b45309;">
                &#9888; Flaw: Binary h<sub>i</sub> = 1 stays flat when editing Subject words.
              </div>
            </div>

            <div style="background: #ffffff; border: 2px solid #dc2626; border-radius: 8px; padding: 12px; box-shadow: 0 2px 6px rgba(220,38,38,0.08);">
              <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: #dc2626; letter-spacing: 0.5px;">
                PROPOSED MODEL &mdash; A-HMFA (OUR IMPROVEMENT)
              </div>
              <div style="font-size: 18px; font-weight: 800; color: #dc2626; margin: 4px 0;">
                ${pa.final_score} / 100
                <span style="font-size: 11px; font-weight: 600; color: #16a34a;">
                  (&Delta; ${(pa.final_score - bp.final_score >= 0 ? '+' : '') + (pa.final_score - bp.final_score).toFixed(2)} vs Paper)
                </span>
              </div>
              <div style="font-family: monospace; font-size: 11.5px; color: #1f2937; line-height: 1.5;">
                S<sub>H</sub>* = &Sigma;(&alpha;<sub>i</sub> &middot; &phi;<sub>i</sub>) + &Psi;<sub>synergy</sub> = <strong>${pa.S_H_star}</strong><br>
                S<sub>final</sub> = ${pa.beta_adaptive}&middot;(S<sub>H</sub>*) + ${(1 - pa.beta_adaptive).toFixed(3)}&middot;(P<sub>ML</sub>) = <strong>${pa.final_score}</strong>
              </div>
              <div style="margin-top: 6px; font-size: 11px; color: #15803d;">
                &#10003; Log-Zone &phi;<sub>i</sub> (Subj 1.75&times;) + Cross-Domain Synergy (&Psi;) + Adaptive &beta;
              </div>
            </div>
          </div>
        `;
      }

      let breakdownHtml = '';
      if (breakdown.length) {
        const rows = breakdown.map(b => {
          const hVal = b.binary_h !== undefined ? b.binary_h : (b.strength > 0 ? 1 : 0);
          const basePts = b.base_contribution !== undefined ? b.base_contribution : (b.weight * hVal * 100);
          return `
            <tr>
              <td><strong>${b.label || FEATURE_LABELS[b.feature] || b.feature}</strong></td>
              <td style="text-align: center;">${b.weight.toFixed(2)}</td>
              <td style="text-align: center; color: #6b7280;">${hVal} (${basePts.toFixed(1)})</td>
              <td style="text-align: center; font-weight: 600; color: #dc2626;">${b.strength.toFixed(3)}</td>
              <td style="text-align: right;"><strong>+${b.contribution.toFixed(2)}</strong></td>
            </tr>
          `;
        }).join('');

        const synergyRow = synergyBonus > 0
          ? `<tr style="background: rgba(254, 226, 226, 0.45);">
               <td colspan="4"><strong>Cross-Domain Attack Chain Synergy (&Psi;<sub>synergy</sub>)</strong> <em>(Spoof &times; URL + Urgency &times; Cred &times; URL)</em></td>
               <td style="text-align: right; color: #dc2626;"><strong>+${synergyBonus.toFixed(2)}</strong></td>
             </tr>`
          : '';

        breakdownHtml = `
          <p class="formula-note" style="margin-top: 16px; font-weight: 600;">
            Comparative Rule Breakdown: Base Paper Binary (h<sub>i</sub> &isin; {0,1}) vs. Proposed Continuous Zone-Density (&phi;<sub>i</sub> &isin; [0,1])
          </p>
          <table class="breakdown-table" style="width: 100%; border-collapse: collapse; margin-top: 6px; background: rgba(255,255,255,0.9); border-radius: 6px; overflow: hidden;">
            <thead>
              <tr style="border-bottom: 2px solid rgba(0,0,0,0.1); text-align: left;">
                <th style="padding: 8px;">Multi-Domain Indicator</th>
                <th style="padding: 8px; text-align: center;">Weight (&alpha;<sub>i</sub>)</th>
                <th style="padding: 8px; text-align: center;">Paper Binary h<sub>i</sub> (Pts)</th>
                <th style="padding: 8px; text-align: center;">Proposed &phi;<sub>i</sub> (0&ndash;1)</th>
                <th style="padding: 8px; text-align: right;">Proposed Pts</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
              ${synergyRow}
              <tr class="breakdown-total" style="border-top: 2px solid rgba(0,0,0,0.15); font-weight: 700;">
                <td colspan="2" style="padding: 8px;">Heuristic Subtotal (S<sub>H</sub> vs. S<sub>H</sub>*)</td>
                <td style="padding: 8px; text-align: center; color: #4b5563;">${baseSh.toFixed(1)} / 100</td>
                <td style="padding: 8px; text-align: center;">&mdash;</td>
                <td style="padding: 8px; text-align: right; color: #dc2626;">${propShStar.toFixed(2)} / 100</td>
              </tr>
            </tbody>
          </table>
        `;
      }

      emailResult.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap;">
          <h4>${isSusp ? 'High-Risk Phishing Email Detected' : 'Low Threat — Normal Communication'}</h4>
          <p style="margin: 0; font-size: 14px; color: var(--text-secondary);">
            Final Hybrid Risk Score: <strong style="font-size: 17px; color: ${isSusp ? '#dc2626' : '#16a34a'};">${data.risk_score} / 100</strong>
          </p>
        </div>
        ${comparisonCardsHtml}
        <div style="margin-top: 14px;">${reasonsHtml}</div>
        ${breakdownHtml}
      `;
    } catch (e) {
      alert('Error analyzing email: ' + e.message);
    }
  });
});
