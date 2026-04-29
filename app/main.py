from flask import Flask, request, jsonify
import requests
import yaml
import ipaddress
import socket
from urllib.parse import urlparse

app = Flask(__name__)

_BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]


def _is_safe_url(url):
    """Return (True, None) or (False, reason) for SSRF validation."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False, "Only http and https schemes are allowed"
        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname"
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            try:
                resolved = socket.getaddrinfo(hostname, None)[0][4][0]
                ip = ipaddress.ip_address(resolved)
            except (socket.gaierror, ValueError):
                return False, "Unable to resolve hostname"
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                return False, "Private or reserved address blocked"
        return True, None
    except Exception:
        return False, "Invalid URL"


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "app": "SecureDeps Demo",
        "version": "1.0.0",
        "status": "running"
    })


@app.route('/fetch', methods=['GET'])
def fetch_url():
    url = request.args.get('url', 'https://httpbin.org/get')
    safe, reason = _is_safe_url(url)
    if not safe:
        return jsonify({"error": "URL blocked", "reason": reason}), 400
    try:
        response = requests.get(url, timeout=10)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": "Request failed", "reason": str(e)}), 502


@app.route('/parse-yaml', methods=['GET'])
def parse_yaml():
    data = request.args.get('data', 'key: value')
    try:
        parsed = yaml.safe_load(data)
        return jsonify(parsed)
    except yaml.YAMLError as e:
        return jsonify({"error": "Invalid YAML", "reason": str(e)}), 400


if __name__ == '__main__':
    app.run(debug=False)
