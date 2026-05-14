exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
  
  try {
    const payload = JSON.parse(event.body);
    
    // 组装发给运营商的头信息 (完美复刻你的 curl)
    let headers = { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${payload.token}`
    };
    if (payload.correlator) headers['x-correlator'] = payload.correlator;

    const res = await fetch('https://opgwtest03.u.com.my/api/transferRest/camc/number-verification/v1/verify', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ phoneNumber: payload.phoneNumber })
    });

    const newCorrelator = res.headers.get('x-correlator') || res.headers.get('correlator') || payload.correlator;
    const data = await res.json();

    return {
      statusCode: res.status,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...data, _correlator: newCorrelator })
    };
  } catch (error) {
    return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
  }
};