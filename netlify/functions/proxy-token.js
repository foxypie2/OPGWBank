const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// ── JWT 常量 ──────────────────────────────────────────────────────────
const TOKEN_URL = 'https://opgwtest03.u.com.my/api/oauth2/camc/token';
const CLIENT_ID = 'OPGWBank';
const KID = 'client-key-2025';

/**
 * 服务端实时生成 client_assertion JWT（不再依赖前端传入）
 * exp 设到 2036 年，一劳永逸
 */
function buildClientAssertion() {
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) throw new Error('Missing PRIVATE_KEY environment variable');

  const now = Math.floor(Date.now() / 1000) - 60; // 60s clock skew buffer
  const payload = {
    iss: CLIENT_ID,
    sub: CLIENT_ID,
    aud: TOKEN_URL,
    iat: now,
    exp: now + 315360000, // 10 years
    jti: crypto.randomBytes(16).toString('hex'),
  };

  return jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    header: { alg: 'RS256', typ: 'JWT', kid: KID },
  });
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };

  try {
    const payload = JSON.parse(event.body);
    const clientAssertion = buildClientAssertion();

    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('code', payload.code);
    params.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    params.append('redirect_uri', 'https://opgw-bank.netlify.app/');
    params.append('client_assertion', clientAssertion);

    let headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (payload.correlator) headers['x-correlator'] = payload.correlator;

    const res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: headers,
      body: params,
    });

    const newCorrelator = res.headers.get('x-correlator') || res.headers.get('correlator') || payload.correlator;
    const data = await res.json();

    return {
      statusCode: res.status,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...data, _correlator: newCorrelator }),
    };
  } catch (error) {
    return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
  }
};