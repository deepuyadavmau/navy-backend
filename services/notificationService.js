const admin = require('firebase-admin');

// Send notification to single user device
const sendNotification = async (deviceToken, title, body, data = {}) => {
  if (!deviceToken) {
    return { success: false, error: 'Device token not found' };
  }

  const message = {
    notification: {
      title,
      body,
    },
    data: Object.keys(data).reduce((acc, key) => {
      acc[key] = String(data[key]);
      return acc;
    }, {}),
    token: deviceToken,
    android: {
      priority: 'high',
      notification: {
        sound: 'default',
        channelId: 'default',
        clickAction: 'FLUTTER_NOTIFICATION_CLICK',
      },
    },
    apns: {
      payload: {
        aps: {
          sound: 'default',
          badge: 1,
        },
      },
    },
  };

  try {
    const response = await admin.messaging().send(message);
    console.log(`✅ Notification sent: ${response}`);
    return { success: true, messageId: response };
  } catch (error) {
    console.error('❌ FCM Error:', error);
    return { success: false, error: error.message };
  }
};

// Send notification to multiple users
const sendToMultipleUsers = async (deviceTokens, title, body, data = {}) => {
  if (!deviceTokens || deviceTokens.length === 0) {
    return { success: false, error: 'No device tokens provided' };
  }

  const message = {
    notification: { title, body },
    data: Object.keys(data).reduce((acc, key) => {
      acc[key] = String(data[key]);
      return acc;
    }, {}),
    android: {
      priority: 'high',
      notification: {
        sound: 'default',
        channelId: 'default',
      },
    },
  };

  try {
    const response = await admin.messaging().sendMulticast({
      ...message,
      tokens: deviceTokens,
    });

    const successCount = response.successCount;
    const failureCount = response.failureCount;

    console.log(`✅ Sent ${successCount} notifications, ${failureCount} failed`);

    if (response.failureCount > 0) {
      const failedTokens = response.responses
        .map((resp, idx) => (!resp.success ? deviceTokens[idx] : null))
        .filter(Boolean);
      console.warn('⚠️ Failed tokens:', failedTokens);
    }

    return {
      success: true,
      sent: successCount,
      failed: failureCount,
      failedTokens: response.responses
        .map((resp, idx) => (!resp.success ? deviceTokens[idx] : null))
        .filter(Boolean),
    };
  } catch (error) {
    console.error('❌ Multicast Error:', error);
    return { success: false, error: error.message };
  }
};

// Send notification to topic (all users subscribed)
const sendToTopic = async (topic, title, body, data = {}) => {
  const message = {
    notification: { title, body },
    data: Object.keys(data).reduce((acc, key) => {
      acc[key] = String(data[key]);
      return acc;
    }, {}),
    topic,
    android: {
      priority: 'high',
      notification: {
        sound: 'default',
        channelId: 'default',
      },
    },
  };

  try {
    const response = await admin.messaging().send(message);
    console.log(`✅ Topic notification sent to ${topic}: ${response}`);
    return { success: true, messageId: response };
  } catch (error) {
    console.error('❌ Topic Error:', error);
    return { success: false, error: error.message };
  }
};

// Subscribe user to topic
const subscribeToTopic = async (deviceToken, topic) => {
  try {
    await admin.messaging().subscribeToTopic([deviceToken], topic);
    console.log(`✅ Device subscribed to topic: ${topic}`);
    return { success: true };
  } catch (error) {
    console.error('❌ Subscribe Error:', error);
    return { success: false, error: error.message };
  }
};

// Unsubscribe user from topic
const unsubscribeFromTopic = async (deviceToken, topic) => {
  try {
    await admin.messaging().unsubscribeFromTopic([deviceToken], topic);
    console.log(`✅ Device unsubscribed from topic: ${topic}`);
    return { success: true };
  } catch (error) {
    console.error('❌ Unsubscribe Error:', error);
    return { success: false, error: error.message };
  }
};

module.exports = {
  sendNotification,
  sendToMultipleUsers,
  sendToTopic,
  subscribeToTopic,
  unsubscribeFromTopic,
};
