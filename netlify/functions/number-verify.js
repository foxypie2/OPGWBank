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
    const { phoneNumber, verified, matchResult, transactionId } = data;

    const docRef = db.collection('opgw_number_verifications').doc(transactionId || Date.now().toString());
    await docRef.set({
      phoneNumber: phoneNumber,
      verified: verified,
      matchResult: matchResult,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return { statusCode: 200, body: JSON.stringify({ message: "Number verification result saved" }) };
  } catch (error) {
    return { statusCode: 500, body: JSON.stringify({ error: "Internal Server Error" }) };
  }
};