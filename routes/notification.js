const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const { sendNotification, sendToMultipleUsers, sendToTopic } = require('../services/notificationService');

// Middleware to check if user exists
const checkUser = async (userId) => {
  return mongoose.connection.collection('users').findOne({ _id: new mongoose.Types.ObjectId(userId) });
};

// ======================== USER ROUTES ========================

// 1. Store device token when user logs in/app starts
router.post('/store-device-token', async (req, res) => {
  try {
    const { userId, deviceToken } = req.body;

    if (!userId || !deviceToken) {
      return res.status(400).json({ error: 'userId and deviceToken required' });
    }

    const User = mongoose.model('User');
    const user = await User.findByIdAndUpdate(
      userId,
      { deviceToken, updatedAt: new Date() },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, message: 'Device token stored', user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. Get user's notification preferences
router.get('/preferences/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const User = mongoose.model('User');
    const user = await User.findById(userId).select('deviceToken email');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ======================== ADMIN ROUTES ========================

// 3. Send notification to specific user
router.post('/admin/send-to-user', async (req, res) => {
  try {
    const { userId, title, body, data = {} } = req.body;

    if (!userId || !title || !body) {
      return res.status(400).json({ error: 'userId, title, and body required' });
    }

    const User = mongoose.model('User');
    const user = await User.findById(userId);

    if (!user || !user.deviceToken) {
      return res.status(404).json({ error: 'User or device token not found' });
    }

    const result = await sendNotification(user.deviceToken, title, body, {
      userId: user._id.toString(),
      sentAt: new Date().toISOString(),
      ...data,
    });

    res.json({ success: result.success, result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 4. Send notification to all users
router.post('/admin/send-to-all', async (req, res) => {
  try {
    const { title, body, data = {} } = req.body;

    if (!title || !body) {
      return res.status(400).json({ error: 'title and body required' });
    }

    const User = mongoose.model('User');
    const users = await User.find({ deviceToken: { $exists: true, $ne: null } });

    if (users.length === 0) {
      return res.status(404).json({ error: 'No users with device tokens found' });
    }

    const deviceTokens = users.map(u => u.deviceToken);
    const result = await sendToMultipleUsers(deviceTokens, title, body, {
      sentAt: new Date().toISOString(),
      ...data,
    });

    res.json({
      success: result.success,
      sent: result.sent,
      failed: result.failed,
      total: deviceTokens.length,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 5. Send notification by role (student, teacher, admin)
router.post('/admin/send-by-role', async (req, res) => {
  try {
    const { role, title, body, data = {} } = req.body;

    if (!role || !title || !body) {
      return res.status(400).json({ error: 'role, title, and body required' });
    }

    const User = mongoose.model('User');
    const users = await User.find({
      role,
      deviceToken: { $exists: true, $ne: null },
    });

    if (users.length === 0) {
      return res.status(404).json({ error: `No ${role}s with device tokens found` });
    }

    const deviceTokens = users.map(u => u.deviceToken);
    const result = await sendToMultipleUsers(deviceTokens, title, body, {
      role,
      sentAt: new Date().toISOString(),
      ...data,
    });

    res.json({
      success: result.success,
      sent: result.sent,
      failed: result.failed,
      total: deviceTokens.length,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 6. Send notification to users with score above threshold
router.post('/admin/send-targeted', async (req, res) => {
  try {
    const { criteria, title, body, data = {} } = req.body;

    if (!criteria || !title || !body) {
      return res.status(400).json({ error: 'criteria, title, and body required' });
    }

    const User = mongoose.model('User');
    const users = await User.find({
      ...criteria,
      deviceToken: { $exists: true, $ne: null },
    });

    if (users.length === 0) {
      return res.status(404).json({ error: 'No users matching criteria with device tokens found' });
    }

    const deviceTokens = users.map(u => u.deviceToken);
    const result = await sendToMultipleUsers(deviceTokens, title, body, {
      sentAt: new Date().toISOString(),
      ...data,
    });

    res.json({
      success: result.success,
      sent: result.sent,
      failed: result.failed,
      total: deviceTokens.length,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 7. Send topic notification (announcements, etc.)
router.post('/admin/send-topic', async (req, res) => {
  try {
    const { topic, title, body, data = {} } = req.body;

    if (!topic || !title || !body) {
      return res.status(400).json({ error: 'topic, title, and body required' });
    }

    const result = await sendToTopic(topic, title, body, {
      sentAt: new Date().toISOString(),
      ...data,
    });

    res.json({ success: result.success, result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 8. Get notification stats
router.get('/admin/stats', async (req, res) => {
  try {
    const User = mongoose.model('User');
    const totalUsers = await User.countDocuments();
    const usersWithTokens = await User.countDocuments({
      deviceToken: { $exists: true, $ne: null },
    });
    const usersByRole = await User.aggregate([
      { $group: { _id: '$role', count: { $sum: 1 } } },
    ]);

    res.json({
      totalUsers,
      usersWithTokens,
      usersWithoutTokens: totalUsers - usersWithTokens,
      usersByRole,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
