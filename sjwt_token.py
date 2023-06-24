import time
import json
import base64
import hashlib
import hmac
import jwt
from flask import request

class JWTManager:

    def __init__(self, jwt_secret_key):
        self.jwt_secret_key = jwt_secret_key

    def generate_token(self, user):
        header = self.base64_url_encode(json.dumps({
            'alg': 'HS256',
            'typ': 'JWT'
        }))

        payload = self.base64_url_encode(json.dumps({
            'iss': 'senad_cavkusic',
            'aud': '.sarajevoweb.com',
            'iat': time.time(),
            'exp': time.time() + 3600,
            'idv': user['id'],
            'ipv': self.get_unique_browser_id()
        }))

        data_to_sign = f"{header}.{payload}"
        signature = self.base64_url_encode(hmac.new(self.jwt_secret_key.encode(), msg=data_to_sign.encode(), digestmod=hashlib.sha256).digest())

        return f"{data_to_sign}.{signature}"

    def get_unique_browser_id(self):
        user_agent = request.headers.get('User-Agent')
        ip_address = request.headers.get('X-Real-IP', request.remote_addr)
        unique_id = hashlib.sha256(f"{user_agent}{ip_address}".encode()).hexdigest()
        return unique_id

    def validate_token(self, token):
        token_parts = token.split('.')
        if len(token_parts) != 3:
            raise Exception('Invalid token format')

        header = json.loads(self.base64_url_decode(token_parts[0]))
        payload = json.loads(self.base64_url_decode(token_parts[1]))
        signature = self.base64_url_decode(token_parts[2])

        if header.get('alg') != 'HS256':
            raise Exception('Unexpected or missing algorithm in token header')

        expected_signature = hmac.new(self.jwt_secret_key.encode(), msg=f"{token_parts[0]}.{token_parts[1]}".encode(), digestmod=hashlib.sha256).digest()
        if not hmac.compare_digest(expected_signature, signature):
            raise Exception('Invalid token signature')

        if payload.get('iss') != 'senad_cavkusic':
            raise Exception('Invalid token issuer')

        if payload.get('exp') and payload['exp'] < time.time():
            raise Exception('Token has expired')

        user_id = payload.get('idv')
        user_ip = self.get_unique_browser_id()
        stored_ip = payload.get('ipv')

        if stored_ip != user_ip:
            raise Exception('Invalid IP address')

        return user_id

    def base64_url_encode(self, data):
        return base64.urlsafe_b64encode(data.encode()).decode().rstrip('=')

    def base64_url_decode(self, data):
        return base64.urlsafe_b64decode(data + '===').decode()
