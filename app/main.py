from flask import Flask, request, jsonify
import requests
import yaml

app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({
        "app": "SecureDeps Demo",
        "version": "1.0.0",
        "status": "running"
    })

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', 'https://httpbin.org/get')
    response = requests.get(url)
    return jsonify(response.json())

@app.route('/parse-yaml')
def parse_yaml():
    data = request.args.get('data', 'key: value')
    parsed = yaml.load(data)
    return jsonify(parsed)

if __name__ == '__main__':
    app.run(debug=True)