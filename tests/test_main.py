import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from main import app

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