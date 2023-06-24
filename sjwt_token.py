import hashlib
import base64
import json
import hmac
import time

jwtSecretKey = "your_jwt_secret_key"

def generate_token(user):
    header = base64_url_encode(json.dumps({
        'alg': 'HS256',
        'typ': 'JWT'
    }))

    payload = base64_url_encode(json.dumps({
        'iss': 'senad_cavkusic',
        'aud': '.sarajevoweb.com',
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600,
        'idv': user['id'],
        'ipv': grab_user_ip_address()
    }))

    data_to_sign = f"{header}.{payload}"
    signature = base64_url_encode(hmac.new(jwtSecretKey.encode(), data_to_sign.encode(), hashlib.sha256).digest())

    return f"{data_to_sign}.{signature}"

def grab_user_ip_address():
    # Retrieve user IP address based on your server environment
    # Implement the logic to get the IP address here
    return user_ip_address

def validate_token(token):
    token_parts = token.split('.')
    if len(token_parts) != 3:
        raise Exception('Invalid token format')

    header_base64 = token_parts[0]
    payload_base64 = token_parts[1]
    signature_base64 = token_parts[2]

    header = json.loads(base64_url_decode(header_base64))
    payload = json.loads(base64_url_decode(payload_base64))
    signature = base64_url_decode(signature_base64)

    # Verify the header
    if 'alg' not in header or header['alg'] != 'HS256':
        raise Exception('Unexpected or missing algorithm in token header')

    # Verify the signature
    expected_signature = hmac.new(jwtSecretKey.encode(), f"{header_base64}.{payload_base64}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected_signature, signature):
        raise Exception('Invalid token signature')

    # Verify the issuer
    if 'iss' not in payload or payload['iss'] != 'senad_cavkusic':
        raise Exception('Invalid token issuer')

    # Verify the token hasn't expired
    if 'exp' in payload and payload['exp'] < int(time.time()):
        raise Exception('Token has expired')

    # Verify the IP address
    user_id = payload.get('idv')
    user_ip = grab_user_ip_address()
    stored_ip = payload.get('ipv')

    if stored_ip != user_ip:
        raise Exception('Invalid IP address')

    return user_id

def base64_url_encode(data):
    encoded_bytes = base64.urlsafe_b64encode(data.encode()).rstrip(b'=')
    return encoded_bytes.decode()

def base64_url_decode(data):
    padding = len(data) % 4
    padded_data = data + '=' * (4 - padding)
    decoded_bytes = base64.urlsafe_b64decode(padded_data.encode())
    return decoded_bytes.decode()
