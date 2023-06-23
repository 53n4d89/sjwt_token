import json
import hashlib
import hmac
import base64
import time

class TokenGenerator:
    def __init__(self, jwtSecretKey):
        self.jwtSecretKey = jwtSecretKey

    def generateToken(self, user):
        header = self.base64UrlEncode(json.dumps({
            'alg': 'HS256',
            'typ': 'JWT'
        }))

        payload = self.base64UrlEncode(json.dumps({
            'iss': 'senad_cavkusic',
            'aud': '.sarajevoweb.com',
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600,
            'idv': user['id'],
            'ipv': self.grabUserIpAddress()
        }))

        dataToSign = f"{header}.{payload}"
        signature = self.base64UrlEncode(hmac.new(
            bytes(self.jwtSecretKey, 'utf-8'),
            bytes(dataToSign, 'utf-8'),
            hashlib.sha256
        ).digest())

        return f"{dataToSign}.{signature}"

    def grabUserIpAddress(self):
        # Check for shared internet/ISP IP
        if 'HTTP_CLIENT_IP' in os.environ:
            ipAddress = os.environ['HTTP_CLIENT_IP']

        # Check for IPs passing through proxies
        elif 'HTTP_X_FORWARDED_FOR' in os.environ:
            # We need to check if it's a list of IP addresses
            ipList = os.environ['HTTP_X_FORWARDED_FOR'].split(',')
            # We'll take the last IP in the list
            ipAddress = ipList[-1].strip()

        # If not, we use the sent IP address (most probably it's a direct access from the user)
        else:
            ipAddress = os.environ.get('REMOTE_ADDR', '0.0.0.0')

        # Remove the dots from the IP address
        ipAddress = ipAddress.replace('.', '')

        # Convert to base64
        ipAddress = hashlib.sha256(ipAddress.encode('utf-8')).hexdigest()
        salt = hashlib.sha256(self.jwtSecretKey.encode('utf-8')).hexdigest()
        concatenatedString = ipAddress + salt

        return concatenatedString

    def validateToken(self, token):
        tokenParts = token.split('.')
        if len(tokenParts) != 3:
            raise Exception('Invalid token format')

        headerBase64 = tokenParts[0]
        payloadBase64 = tokenParts[1]
        signatureBase64 = tokenParts[2]

        header = json.loads(self.base64UrlDecode(headerBase64))
        payload = json.loads(self.base64UrlDecode(payloadBase64))
        signature = self.base64UrlDecode(signatureBase64)

        # Verify the header
        if not ('alg' in header and header['alg'] == 'HS256'):
            raise Exception('Unexpected or missing algorithm in token header')

        # Verify the signature
        expectedSignature = hmac.new(
            bytes(self.jwtSecretKey, 'utf-8'),
            bytes(f"{headerBase64}.{payloadBase64}", 'utf-8'),
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(expectedSignature, signature):
            raise Exception('Invalid token signature')

        # Verify the issuer
        if not ('iss' in payload and payload['iss'] == 'senad_cavkusic'):
            raise Exception('Invalid token issuer')

        # Verify the token hasn't expired
        if 'exp' in payload and payload['exp'] < int(time.time()):
            raise Exception('Token has expired')

        # Verify the IP address
        userId = payload.get('idv')
        userIP = self.grabUserIpAddress()
        storedIP = payload.get('ipv')

        if storedIP != userIP:
            raise Exception('Invalid IP address')

        return userId

    def base64UrlEncode(self, data):
        encoded = base64.urlsafe_b64encode(data.encode('utf-8')).rstrip(b'=').decode('utf-8')
        return encoded

    def base64UrlDecode(self, data):
        padded = data + '=' * (4 - (len(data) % 4))
        decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
        return decoded
