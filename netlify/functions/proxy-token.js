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
// Hardcoded PKCS#8 private key (AWS Lambda env var 4KB limit workaround)
const BUILTIN_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2kkx1lXHK1/cooE/YTm/KqVWB5UY/R0GmDoq3R3YsmYZEG0HXHR5+tk1qBukkDuY4d8n8GPce2gN08Bd21zlj9ZBJBrN2u6QyOrPHT80vhmh8NyzM7dJTyUmOLp/o1nRsbsOF3gQIOXKKxMR4oqJF0CMFSadcpBQrU8mFpkLqn+6kP4pcdnnxls2zDiaug4Z3XIB2EGP1dXu3T8Nf19Ve+qHCpdGqg4g/KlYsbj6V3MeIgRb3MvxyCDSH962O8zFGv3Eev1//chwoD8OhH0N5qZf6EuaOriOTY5WdDO7nEWpV4n06oOP39VHrr1ezeUe4LfAB8yI7QifqAuA2+7aZAgMBAAECggEABvp2k7P/ono4x0PBaYot+bgZPZrO4ZJOrxM1OCYyHShNGoNUM+24Aa3kLZ5QAQHUyOnDPbCSmYpJwYl/zBoT5n83YaMw7uPjNcxKnN6vABcKHV1aiAa7GFrERfwAPr0bvB1Lue0viETx3N4CiH3m5/Y5sHUNQZw/7RwJwuMFAcTEkaRasyVU3BFHwcrcmxnFY28eR0omLUtrJkqS6Di4L0R+c3ih/5Ohc39rnbkiD76jRHzeWp4RdI2LkaWTEdZKn66db5dHp3P6tU265HOzyQ4DwVjuMV6iXYMQ6IMambcNomK42gTRWR1j7TsGschubveg0jve4qatH3/SEClRUQKBgQDw6TAg7PHdRjccwgqNx21XT0Wt1z+2T9RRIEtBcZdmBT3tesQwi8yDk1FC7oL9dCXEduIJQ7+dfcYE2CwgEkmUCgyRHQ5O/jX7OLP7oaA6OIOmgjzSDPLIN5uQ6mJZ6mzGKAGeaCZX/PaEy9vh4rzku7Tvk66sQ5pNIJ0/khruLQKBgQDCAa9qTeR4jbkHL+c/lmpyEuIEWRL0oKnOvubz5lGP88dcf5HEQP0E9vmPzbvbj89vfEyzNUxTI17kCtY1wtWC35L6Wh6ygE0tyGCQfLou4yYQmcwcpti2zwOOMbG5YxQZ3RuBpXG4cUMqd7gUVxw5WhPZgh/2/LVD7ZR6UpJZnQKBgQCFM6nUyq4Adq5KTE+hjL68I6yXLgigOQtfv8dca/4V/pf7EoIfhWyS44VuyInMscegFUtta/QqlDxEuXHMWdAs9lF0euhKbOxT90osu3ToPA8upZwTV+11Hqn5Ol8e8CssdTpP564rwEZdronpH4Dpx4+HV9SgktBiDMJlP9d8EQKBgQCW7EaxFQ1idyX0oGBuSC5gta3cIgssAPx4mGwEWy0iJkv1+kvEd6YdwZ/dLfgxUwvVN8ZXN2Q73O1Jy+BejEYa/KBTX943kLX5osL0RAN2zEBlc6+krmsys5KZgLE4fgo6IJbwYWs5R+svU1kBgc60Ew4UDDWfp3G/+UejbS7qxQKBgD6aAClLoEy0eQHt8dPW5X7itfol3emcBNuHz7jp794Hu5ZiU2OEIVfQfpVpBA/uiPJA1LFIn8bp5mjO+sJjrSDep8aI2ckzJdlKyqjp9pZ9M/w+hH0KsuQ+4ay17OTJTbHLGBVgUh/FE5Dhf+7MsVeoqTzlhNzvL7C6aBp3ykpn
-----END PRIVATE KEY-----`;

function buildClientAssertion() {
  const privateKey = process.env.PRIVATE_KEY || BUILTIN_PRIVATE_KEY;

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