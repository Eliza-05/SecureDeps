import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from main import app


# ── Tests originales (deben seguir pasando) ────────────────────────

def test_index():
    client = app.test_client()
    response = client.get('/')
    assert response.status_code == 200


def test_index_returns_json():
    client = app.test_client()
    response = client.get('/')
    data = response.get_json()
    assert data['app'] == 'SecureDeps Demo'
    assert data['status'] == 'running'


# ── SSRF validation (/fetch) ───────────────────────────────────────

def test_fetch_blocks_ssrf_localhost():
    client = app.test_client()
    response = client.get('/fetch', query_string={'url': 'http://127.0.0.1/'})
    assert response.status_code == 400


def test_fetch_blocks_ssrf_metadata():
    client = app.test_client()
    response = client.get('/fetch', query_string={'url': 'http://169.254.169.254/'})
    assert response.status_code == 400


def test_fetch_blocks_private_range():
    client = app.test_client()
    response = client.get('/fetch', query_string={'url': 'http://192.168.1.1/'})
    assert response.status_code == 400


def test_fetch_blocks_non_http_scheme():
    client = app.test_client()
    response = client.get('/fetch', query_string={'url': 'file:///etc/passwd'})
    assert response.status_code == 400


# ── YAML safe load (/parse-yaml) ───────────────────────────────────

def test_parse_yaml_safe_input():
    client = app.test_client()
    response = client.get('/parse-yaml', query_string={'data': 'key: value'})
    assert response.status_code == 200
    assert response.get_json() == {'key': 'value'}


def test_parse_yaml_rejects_dangerous_payload():
    # yaml.safe_load raises ConstructorError for !!python/* tags;
    # the endpoint must return 400, not crash with 500.
    client = app.test_client()
    response = client.get(
        '/parse-yaml',
        query_string={'data': '!!python/object/apply:os.system ["id"]'}
    )
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data


# ── Security headers ───────────────────────────────────────────────

def test_security_headers_present():
    client = app.test_client()
    response = client.get('/')
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('X-XSS-Protection') == '1; mode=block'
    assert 'Content-Security-Policy' in response.headers
