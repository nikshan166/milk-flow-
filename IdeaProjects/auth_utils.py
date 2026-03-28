import re
import functools
from datetime import datetime, timezone
from flask import request, jsonify
import jwt

JWT_SECRET = 'milkflow-secret-key'
JWT_ALGO = 'HS256'


def validate_email(email):
    return bool(email and re.match(r"^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$", email))


def validate_password(password):
    return bool(password and len(password) >= 6)


def validate_role(role):
    return role in ('farmer', 'customer', 'admin')


def create_token(user_id, role):
    payload = {
        'sub': user_id,
        'role': role,
        'iat': int(datetime.now(tz=timezone.utc).timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        return None


def get_token_from_request():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth.split(' ', 1)[1].strip()
    return None


def token_required(role=None):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            token = get_token_from_request()
            if not token:
                return jsonify(success=False, message='Missing auth token'), 401
            data = decode_token(token)
            if not data:
                return jsonify(success=False, message='Invalid or expired token'), 401
            if role and data.get('role') != role:
                return jsonify(success=False, message='Unauthorized role'), 403
            request.user = data
            return fn(*args, **kwargs)
        return wrapper
    return decorator
