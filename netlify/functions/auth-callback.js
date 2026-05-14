const admin = require('firebase-admin');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))
  });
}

const db = admin.firestore();

exports.handler = async (event, context) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }
  try {
    const data = JSON.parse(event.body);
    const { authCode, token, userId } = data;

    const docRef = db.collection('opgw_auth_records').doc(userId || Date.now().toString());
    await docRef.set({
      authCode: authCode,
      token: token,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return { statusCode: 200, body: JSON.stringify({ message: "Auth record saved successfully" }) };
  } catch (error) {
    return { statusCode: 500, body: JSON.stringify({ error: "Internal Server Error" }) };
  }
};