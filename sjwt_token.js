const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const jwtSecretKey = 'your_secret_key';

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
    ipv: getUniqueBrowserId()
  }));

  const dataToSign = `${header}.${payload}`;
  const signature = base64UrlEncode(
    crypto
      .createHmac('sha256', jwtSecretKey)
      .update(dataToSign)
      .digest('binary')
  );

  return `${dataToSign}.${signature}`;
}

function getUniqueBrowserId() {
  const userAgent = req.headers['user-agent'];
  const ipAddress =
    req.headers['x-forwarded-for'] ||
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    req.connection.socket.remoteAddress;

  const ipWithoutDots = ipAddress.replace(/\./g, '');
  const uniqueId = crypto.createHash('sha256').update(userAgent + ipWithoutDots).digest('hex');

  return uniqueId;
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

  if (!header.alg || header.alg !== 'HS256') {
    throw new Error('Unexpected or missing algorithm in token header');
  }

  const expectedSignature = crypto
    .createHmac('sha256', jwtSecretKey)
    .update(`${headerBase64}.${payloadBase64}`)
    .digest('binary');

  if (!crypto.timingSafeEqual(Buffer.from(expectedSignature, 'binary'), Buffer.from(signature, 'binary'))) {
    throw new Error('Invalid token signature');
  }

  if (!payload.iss || payload.iss !== 'senad_cavkusic') {
    throw new Error('Invalid token issuer');
  }

  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token has expired');
  }

  const userId = payload.idv || null;
  const userIP = getUniqueBrowserId();
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
  const paddingLength = (4 - (data.length % 4)) % 4;
  const paddedData = data + '='.repeat(paddingLength);
  return Buffer.from(paddedData, 'base64').toString();
}

module.exports = {
  generateToken,
  validateToken
};
