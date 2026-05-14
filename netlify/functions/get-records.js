const admin = require('firebase-admin');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))
  });
}

const db = admin.firestore();

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') return { statusCode: 405, body: 'Method Not Allowed' };
  
  const correlator = event.queryStringParameters.id;
  if (!correlator) return { statusCode: 400, body: JSON.stringify({ error: '缺少 correlation id' }) };

  try {
    // 同时去两个表里查这个 ID
    const authRef = await db.collection('opgw_auth_records').doc(correlator).get();
    const nvRef = await db.collection('opgw_number_verifications').doc(correlator).get();

    return {
      statusCode: 200,
      body: JSON.stringify({
        correlation_id: correlator,
        auth_and_token_result: authRef.exists ? authRef.data() : "暂无记录",
        number_verification_result: nvRef.exists ? nvRef.data() : "暂无记录"
      })
    };
  } catch (error) {
    return { statusCode: 500, body: JSON.stringify({ error: "服务器内部错误" }) };
  }
};