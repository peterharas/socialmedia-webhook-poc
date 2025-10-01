import os
import hmac
import hashlib
import json
from flask import Flask, request, Response, render_template

# CODE ADAPTED AND CONVERT TO PYTHON USING COPILOT FROM: https://github.com/fbsamples/graph-api-webhooks-samples/blob/main/heroku/index.js

app = Flask(__name__)

# Environment variables (with defaults)
PORT = int(os.environ.get('PORT', 5000))
APP_SECRET = os.environ.get('APP_SECRET', '')  # required for X-Hub validation
TOKEN = os.environ.get('TOKEN', 'token')

# Store recent updates (like the Node.js received_updates.unshift)
received_updates = []  # newest first


def verify_xhub_signature(app_secret: str, raw_body: bytes, signature_header: str) -> bool:
    """
    Validate X-Hub-Signature header against the HMAC-SHA1 of the raw request body.
    Header format: 'sha1=hexdigest'
    """
    if not app_secret or not signature_header:
        return False

    try:
        method, received_sig = signature_header.split('=', 1)
    except ValueError:
        return False

    if method.lower() != 'sha1':
        # This server mirrors your Node app and only validates sha1
        return False

    expected = hmac.new(app_secret.encode('utf-8'), raw_body, hashlib.sha1).hexdigest()
    return hmac.compare_digest(expected, received_sig)


@app.route('/received', methods=['GET'])
def received():
    """Render collected updates as pretty-printed JSON in <pre>."""
    body = '<pre>' + json.dumps(received_updates, indent=2, ensure_ascii=False) + '</pre>'
    return Response(body, mimetype='text/html')


@app.route('/', methods=['GET'])
def index():
    render_template('privacy-policy.html')


@app.route('/privacy', methods=['GET'])
def privacy():
    render_template('privacy-policy.html')


# Verification endpoints (Facebook/Instagram/Threads) — same logic for all three
@app.get('/facebook')
@app.get('/instagram')
@app.get('/threads')
def verify():
    mode = request.args.get('hub.mode')
    verify_token = request.args.get('hub.verify_token')
    challenge = request.args.get('hub.challenge', '')

    if mode == 'subscribe' and verify_token == TOKEN:
        # Return the challenge string
        return Response(challenge, status=200, mimetype='text/plain')

    return '', 400


# Webhook receiver for Facebook with X-Hub-Signature validation
@app.post('/facebook')
def facebook_webhook():
    raw = request.get_data() or b''
    print('Facebook request body:', raw.decode('utf-8', errors='replace'))

    signature = request.headers.get('X-Hub-Signature')  # format: 'sha1=...'
    if not verify_xhub_signature(APP_SECRET, raw, signature):
        print('Warning - request header X-Hub-Signature not present or invalid')
        return '', 401

    print('request header X-Hub-Signature validated')
    payload = request.get_json(silent=True)
    received_updates.insert(0, payload if payload is not None else raw.decode('utf-8', errors='replace'))
    return '', 200


# Webhook receivers for Instagram and Threads (no signature validation in your original code)
@app.post('/instagram')
def instagram_webhook():
    payload = request.get_json(silent=True)
    print('Instagram request body:', payload if payload is not None else request.get_data(as_text=True))
    received_updates.insert(0, payload if payload is not None else request.get_data(as_text=True))
    return '', 200


@app.post('/threads')
def threads_webhook():
    payload = request.get_json(silent=True)
    print('Threads request body:', payload if payload is not None else request.get_data(as_text=True))
    received_updates.insert(0, payload if payload is not None else request.get_data(as_text=True))
    return '', 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=PORT)
