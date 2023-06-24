const crypto = require('crypto');

function generateToken(user) {
  const header = base64UrlEncode(JSON.stringify({
    alg: 'HS256',
    typ: 'JWT'
  }));

  const payload = base64UrlEncode(JSON.stringify({
    iss: 'senad_cavkusic',
    aud: '.sarajevoweb.com',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    idv: user.id,
    ipv: grabUserIpAddress()
  }));

  const dataToSign = `${header}.${payload}`;
  const signature = base64UrlEncode(crypto.createHmac('sha256', jwtSecretKey).update(dataToSign).digest('binary'));

  return `${dataToSign}.${signature}`;
}

function grabUserIpAddress() {
  const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress || '0.0.0.0';
  const ipAddressWithoutDots = ipAddress.replace(/\./g, '');
  const salt = crypto.createHash('sha256').update(jwtSecretKey).digest('hex');
  const concatenatedString = ipAddressWithoutDots + salt;

  return crypto.createHash('sha256').update(concatenatedString).digest('hex');
}

function validateToken(token) {
  const tokenParts = token.split('.');
  if (tokenParts.length !== 3) {
    throw new Error('Invalid token format');
  }

  const headerBase64 = tokenParts[0];
  const payloadBase64 = tokenParts[1];
  const signatureBase64 = tokenParts[2];

  const header = JSON.parse(base64UrlDecode(headerBase64));
  const payload = JSON.parse(base64UrlDecode(payloadBase64));
  const signature = base64UrlDecode(signatureBase64);

  // Verify the header
  if (!header.alg || header.alg !== 'HS256') {
    throw new Error('Unexpected or missing algorithm in token header');
  }

  // Verify the signature
  const expectedSignature = crypto.createHmac('sha256', jwtSecretKey).update(`${headerBase64}.${payloadBase64}`).digest('binary');
  if (!crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signature))) {
    throw new Error('Invalid token signature');
  }

  // Verify the issuer
  if (!payload.iss || payload.iss !== 'senad_cavkusic') {
    throw new Error('Invalid token issuer');
  }

  // Verify the token hasn't expired
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token has expired');
  }

  // Verify the IP address
  const userId = payload.idv || null;
  const userIP = grabUserIpAddress();
  const storedIP = payload.ipv || null;

  if (storedIP !== userIP) {
    throw new Error('Invalid IP address');
  }

  return userId;
}

function base64UrlEncode(data) {
  let encoded = Buffer.from(data).toString('base64');
  encoded = encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  return encoded;
}

function base64UrlDecode(data) {
  const padded = data + '==='.slice((data.length + 3) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

module.exports = {
  generateToken,
  validateToken
  base64UrlEncode,
  base64UrlDecode
};
