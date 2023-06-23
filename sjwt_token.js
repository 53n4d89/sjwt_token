const crypto = require('crypto');

class TokenGenerator {
  constructor(jwtSecretKey) {
    this.jwtSecretKey = jwtSecretKey;
  }

  generateToken(user) {
    const header = this.base64UrlEncode(JSON.stringify({
      alg: 'HS256',
      typ: 'JWT'
    }));

    const payload = this.base64UrlEncode(JSON.stringify({
      iss: 'senad_cavkusic',
      aud: '.sarajevoweb.com',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      idv: user.id,
      ipv: this.grabUserIpAddress()
    }));

    const dataToSign = `${header}.${payload}`;
    const signature = this.base64UrlEncode(
      crypto
        .createHmac('sha256', this.jwtSecretKey)
        .update(dataToSign)
        .digest('binary')
    );

    return `${dataToSign}.${signature}`;
  }

  grabUserIpAddress(request) {
    let ipAddress = '0.0.0.0';

    if (request.headers['x-forwarded-for']) {
      const ipList = request.headers['x-forwarded-for'].split(',');
      ipAddress = ipList[ipList.length - 1].trim();
    } else if (request.connection && request.connection.remoteAddress) {
      ipAddress = request.connection.remoteAddress;
    }

    ipAddress = ipAddress.replace(/[^0-9.]/g, '');
    const hashedIpAddress = crypto.createHash('sha256').update(ipAddress).digest('hex');
    const salt = crypto.createHash('sha256').update(this.jwtSecretKey).digest('hex');
    const concatenatedString = hashedIpAddress + salt;

    return concatenatedString;
  }

  validateToken(token) {
    const tokenParts = token.split('.');
    if (tokenParts.length !== 3) {
      throw new Error('Invalid token format');
    }

    const headerBase64 = tokenParts[0];
    const payloadBase64 = tokenParts[1];
    const signatureBase64 = tokenParts[2];

    const header = JSON.parse(this.base64UrlDecode(headerBase64));
    const payload = JSON.parse(this.base64UrlDecode(payloadBase64));
    const signature = this.base64UrlDecode(signatureBase64);

    // Verify the header
    if (!header || header.alg !== 'HS256') {
      throw new Error('Unexpected or missing algorithm in token header');
    }

    // Verify the signature
    const expectedSignature = crypto
      .createHmac('sha256', this.jwtSecretKey)
      .update(`${headerBase64}.${payloadBase64}`)
      .digest('binary');

    if (!crypto.timingSafeEqual(Buffer.from(expectedSignature, 'binary'), Buffer.from(signature, 'binary'))) {
      throw new Error('Invalid token signature');
    }

    // Verify the issuer
    if (!payload || payload.iss !== 'senad_cavkusic') {
      throw new Error('Invalid token issuer');
    }

    // Verify the token hasn't expired
    const currentTime = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < currentTime) {
      throw new Error('Token has expired');
    }

    // Verify the IP address
    const userId = payload.idv || null;
    const userIP = this.grabUserIpAddress();
    const storedIP = payload.ipv || null;

    if (storedIP !== userIP) {
      throw new Error('Invalid IP address');
    }

    return userId;
  }

  base64UrlEncode(data) {
    let encoded = Buffer.from(data).toString('base64');
    encoded = encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    return encoded;
  }

  base64UrlDecode(data) {
    let paddingLength = 4 - (data.length % 4);
    if (paddingLength === 4) {
      paddingLength = 0;
    }

    const paddedData = data + '='.repeat(paddingLength);
    const decoded = Buffer.from(paddedData.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();

    return decoded;
  }
}

module.exports = TokenGenerator;
