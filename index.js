require('dotenv').config(); 
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken'); 
const helmet = require("helmet"); 
const rateLimit = require("express-rate-limit"); 
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");
const serviceAccount = require('./firebase-key.json');

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId: serviceAccount.project_id,
});

const app = express();
app.set("trust proxy", 1);
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// --- 1. SECURITY MIDDLEWARES ---
app.use(express.json({ limit: '10mb' })); // Limit payload size
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Security Headers (Helmet)
app.use(helmet());

// CORS Configuration
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:5000",
  "https://localhost:5173",
  "https://localhost:3000",
  // DevTunnel URLs (development)
  /\.inc1\.devtunnels\.ms$/,
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Check if origin matches any allowed origin or pattern
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (allowedOrigin instanceof RegExp) {
        return allowedOrigin.test(origin);
      }
      return allowedOrigin === origin;
    });

    if (isAllowed) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Rate Limiting - General
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests, please try again later'
});

// Rate Limiting - Admin Routes (Stricter)
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // Max 30 requests per 15 minutes
  message: '🚨 Too many admin requests - possible attack detected',
  keyGenerator: (req) => req.user?.id || req.ip // Per user/IP
});

// Rate Limiting - Bulk Upload (Very Strict)
const bulkUploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Max 5 bulk uploads per hour
  message: '⚠️ Bulk upload limit exceeded - try again later',
  keyGenerator: (req) => req.user?.id || req.ip
});

// Apply general rate limiting
app.use(generalLimiter);

// --- 2. DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Iron-Clad DB Connected"))
  .catch((err) => console.log("❌ DB Connection Error:", err));

// --- 3. MODELS ---
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, default: "student" },
  banned: { type: Boolean, default: false },
  solvedQuestions: { type: [mongoose.Schema.Types.ObjectId], ref: "Question", default: [] },
  // ✅ Activity Stats Added (Subject wise permanent storage)
  activityStats: {
    math: { correct: { type: Number, default: 0 }, wrong: { type: Number, default: 0 } },
    science: { correct: { type: Number, default: 0 }, wrong: { type: Number, default: 0 } },
    gk: { correct: { type: Number, default: 0 }, wrong: { type: Number, default: 0 } }
  },
  resetOtp: { type: String },
  resetOtpExpires: { type: Date },
  deviceToken: { type: String, default: null },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", UserSchema);

const Question = mongoose.model("Question", new mongoose.Schema({
  exam: String, subject: String, chapter: String, question: String, options: [String], answer: String,      
}));

// Audit Log Model - Track all admin actions for security
const AuditLogSchema = new mongoose.Schema({
  adminId: mongoose.Schema.Types.ObjectId,
  adminEmail: String,
  action: String,
  resource: String, // "user", "question", "system"
  resourceId: String,
  details: {},
  ipAddress: String,
  timestamp: { type: Date, default: Date.now },
  status: String // "success", "failed"
});
const AuditLog = mongoose.model("AuditLog", AuditLogSchema);

// Helper function to log admin actions
const logAdminAction = async (req, res, next) => {
  req.logAudit = async (action, resource, resourceId, details = {}) => {
    try {
      const auditEntry = new AuditLog({
        adminId: req.user?.id,
        adminEmail: req.user?.email,
        action,
        resource,
        resourceId,
        details,
        ipAddress: req.ip,
        status: "success"
      });
      await auditEntry.save();
    } catch (err) {
      console.error("Audit logging error:", err);
    }
  };
  next();
};

// --- 4. PROTECTION MIDDLEWARES ---

const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access Denied. Login First!" });
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or Expired Token" });
  }
};

const isAdmin = async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (user && (user.role === "admin" || user.email === "aadi@gmail.com")) { 
    next();
  } else {
    res.status(403).json({ message: "Sirf Admin hi access kar sakta hai!" });
  }
};

// Input Validation & Sanitization
const validateInput = (req, res, next) => {
  // Reject payloads that are too large
  if (JSON.stringify(req.body).length > 50000) {
    return res.status(400).json({ message: "❌ Payload too large" });
  }
  
  // Sanitize string inputs - remove dangerous characters
  const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return str.trim().slice(0, 500); // Limit to 500 chars
  };

  const sanitizeObject = (obj) => {
    if (Array.isArray(obj)) {
      return obj.map(sanitizeObject);
    } else if (obj !== null && typeof obj === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = sanitizeObject(value);
      }
      return sanitized;
    } else if (typeof obj === 'string') {
      return sanitizeString(obj);
    }
    return obj;
  };

  req.body = sanitizeObject(req.body);
  next();
};

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '30d' });
};

// --- 5. AUTH ROUTES ---

app.post("/api/google-login", async (req, res) => {
  const { idToken } = req.body;
  try {
    const ticket = await client.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID });
    const { email, name } = ticket.getPayload();
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ name, email, password: Math.random().toString(36) });
      await user.save();
    }
    const token = generateToken(user._id);
    res.json({ success: true, user, token });
  } catch (err) { res.status(401).json({ success: false, message: "Google Auth Failed" }); }
});

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ success: false, message: "Email already registered" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = generateToken(user._id);
    res.json({ success: true, message: "User saved successfully", user: { _id: user._id, name: user.name, email: user.email }, token });
  } catch (err) { res.status(500).json({ success: false, message: "Signup Error" }); }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ success: false, message: "Invalid credentials" });

    const token = generateToken(user._id);
    res.json({ success: true, user, token });
  } catch (err) { res.status(500).json({ success: false, message: "Login Error" }); }
});

// --- 6. DATA ROUTES ---

// 🔥 NEW: Permanent Activity Update Route
app.post("/api/update-activity", authenticateToken, async (req, res) => {
  try {
    const { subject, isCorrect } = req.body;
    // Dynamic field path based on subject and result
    const field = `activityStats.${subject}.${isCorrect ? 'correct' : 'wrong'}`;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { $inc: { [field]: 1 } }, // Increment by 1
      { new: true }
    ).select("-password");

    res.json({ success: true, user: updatedUser });
  } catch (err) {
    res.status(500).json({ success: false, message: "Activity Sync Failed" });
  }
});

app.get("/api/leaderboard", async (req, res) => {
  try {
    const topUsers = await User.find().select("name solvedQuestions").lean();
    const sorted = topUsers.map(u => ({
      name: u.name,
      score: u.solvedQuestions.length
    })).sort((a, b) => b.score - a.score).slice(0, 10);
    res.json(sorted);
  } catch (err) { res.status(500).json({ message: "Leaderboard Error" }); }
});

app.post("/api/mark-solved", authenticateToken, async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id, 
      { $addToSet: { solvedQuestions: { $each: req.body.questionIds } } },
      { new: true } 
    ).select("-password");
    res.json({ success: true, user: updatedUser });
  } catch (err) { res.status(500).json({ message: "Update Error" }); }
});

app.get("/api/get-test/:userId/:exam", authenticateToken, async (req, res) => {
  try {
    const { exam } = req.params;
    const user = await User.findById(req.user.id);
    const solvedIds = user?.solvedQuestions || [];

    // Fetch 25 GK questions (unsolved only)
    const gkQuestions = await Question.find({ 
      exam: { $regex: new RegExp(`^${exam}$`, "i") }, 
      subject: { $regex: /^GK$/i },
      _id: { $nin: solvedIds } 
    }).limit(25);

    // Fetch 13 Science questions (unsolved only)
    const scienceQuestions = await Question.find({ 
      exam: { $regex: new RegExp(`^${exam}$`, "i") }, 
      subject: { $regex: /^Science$/i },
      _id: { $nin: solvedIds } 
    }).limit(13);

    // Fetch 12 Math questions (unsolved only)
    const mathQuestions = await Question.find({ 
      exam: { $regex: new RegExp(`^${exam}$`, "i") }, 
      subject: { $regex: /^Math$/i },
      _id: { $nin: solvedIds } 
    }).limit(12);

    // Combine all questions
    const allQuestions = [...gkQuestions, ...scienceQuestions, ...mathQuestions];
    
    // Return with count info for frontend validation
    res.json({
      questions: allQuestions.sort(() => Math.random() - 0.5),
      total: allQuestions.length,
      gk: gkQuestions.length,
      science: scienceQuestions.length,
      math: mathQuestions.length
    });
  } catch (err) { 
    res.status(500).json({ message: "Test Error" }); 
  }
});

app.get("/api/practice/:exam/:subject", authenticateToken, async (req, res) => {
  try {
    const { exam, subject } = req.params;    
    const questions = await Question.find({ 
      exam: { $regex: new RegExp(`^${exam}$`, "i") }, 
      subject: { $regex: new RegExp(`^${subject}$`, "i") } 
    });
    res.json(questions);
  } catch (err) { res.status(500).json({ message: "Practice Error" }); }
});

app.get("/api/syllabus/:exam/:subject/:chapter", authenticateToken, async (req, res) => {
    try {
      const { exam, subject, chapter } = req.params;
      const data = await Question.find({ 
        exam: { $regex: new RegExp(`^${exam}$`, "i") }, 
        subject: { $regex: new RegExp(`^${subject}$`, "i") },
        chapter: { $regex: new RegExp(`^${chapter}$`, "i") }
      });
      res.json(data);
    } catch (err) { res.status(500).json({ message: "Syllabus Error" }); }
});


app.get("/api/user/:userId", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json({ success: true, user });
  } catch (err) { res.status(500).json({ success: false, message: "User Error" }); }
});


// --- 7. PASSWORD RESET ROUTES (OTP based) ---
// --- 1. Nodemailer Transporter Setup ---
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});


// --- 2. Route: OTP Bhejna (Forgot Password) ---
app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    // 🔍 Email check (Trim and Lowercase)
    const formattedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: formattedEmail });
    
    if (!user) {
      return res.status(404).json({ success: false, message: "Email not found! Please create an account." });
    }

    // 🔢 6-Digit OTP generate
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // 💾 Save to DB
    user.resetOtp = otp;
    user.resetOtpExpires = Date.now() + 600000; // 10 Min Expiry
    await user.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: formattedEmail,
      subject: "Security Code: Password Reset",
      html: `
        <div style="font-family: sans-serif; text-align: center; border: 1px solid #e2e8f0; padding: 25px; border-radius: 20px; max-width: 400px; margin: auto;">
          <h2 style="color: #2563eb;">Reset Your Password</h2>
          <p style="color: #475569;">Your security code is below:</p>
          <h1 style="letter-spacing: 8px; color: #1e293b; background: #f8fafc; padding: 15px; border-radius: 10px;">${otp}</h1>
          <p style="color: #94a3b8; font-size: 12px;">This code will expire in 10 minutes. If you didn't request this, please ignore it.</p>
        </div>`
    };

    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: "OTP sent successfully!" });

  } catch (err) {
    console.error("Forgot Pass Error:", err);
    res.status(500).json({ success: false, message: "Error sending email!" });
  }
});

// --- 3. Route: OTP Verify & Password Reset ---
// --- OTP Bhejna (Forgot Password) ---
app.post("/api/forgot-password", async (req, res) => {
  try {
    // 1. Email ko saaf karein (Lowercase + Trim)
    const email = req.body.email.toLowerCase().trim();
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ success: false, message: "Email not found!" });
    }

    // 2. OTP generate aur string mein convert
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // 3. Database mein save (Verify karein ki save ho raha hai)
    user.resetOtp = otp;
    user.resetOtpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 Min
    await user.save();
    console.log(`✅ OTP for ${email} is: ${otp}`); // Debugging ke liye terminal check karein

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset OTP",
      html: `<div style="text-align:center; padding:20px; border:1px solid #ddd; border-radius:10px;">
              <h2>Verification Code</h2>
              <h1 style="letter-spacing:5px; color:#2563eb;">${otp}</h1>
              <p>Valid for 10 minutes only.</p>
             </div>`
    };

    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: "OTP sent successfully!" });

  } catch (err) {
    res.status(500).json({ success: false, message: "Server error!" });
  }
});

// --- OTP Verify (Reset Password) ---
app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    // 🔍 Sabse Important Check: Data ko clean karein
    const cleanEmail = email.toLowerCase().trim();
    const cleanOtp = otp.toString().trim();

    // Debugging: Terminal mein dekhiye kya aa raha hai
    console.log(`Verifying: Email: ${cleanEmail}, OTP: ${cleanOtp}`);

    const user = await User.findOne({ 
      email: cleanEmail, 
      resetOtp: cleanOtp, 
      resetOtpExpires: { $gt: Date.now() } 
    });

    if (!user) {
      // Agar user nahi mila toh reason check karein
      const checkUser = await User.findOne({ email: cleanEmail });
      if (!checkUser) return res.status(400).json({ message: "User not found!" });
      if (checkUser.resetOtp !== cleanOtp) return res.status(400).json({ message: "Invalid OTP code!" });
      return res.status(400).json({ message: "OTP has expired!" });
    }

    // 🔒 Password change logic
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    
    // OTP clear karein
    user.resetOtp = undefined;
    user.resetOtpExpires = undefined;
    
    await user.save();
    res.json({ success: true, message: "Password changed successfully!" });

  } catch (err) {
    res.status(500).json({ success: false, message: "Reset process failed!" });
  }
});

// --- 8. ADMIN ROUTES (with rate limiting, validation, and audit logging) ---

// Get all users
app.get("/api/admin/users", adminLimiter, authenticateToken, isAdmin, logAdminAction, async (req, res) => {
  try {
    const users = await User.find().select("-password");
    await req.logAudit("VIEW_USERS", "user", "bulk", { count: users.length });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch users" });
  }
});

// Delete user
app.delete("/api/admin/users/:userId", adminLimiter, authenticateToken, isAdmin, logAdminAction, async (req, res) => {
  try {
    const userId = req.params.userId;
    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "❌ Invalid user ID" });
    }
    const user = await User.findByIdAndDelete(userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    
    await req.logAudit("DELETE_USER", "user", userId, { userEmail: user.email });
    res.json({ success: true, message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete user" });
  }
});

// Ban user
app.put("/api/admin/users/:userId/ban", adminLimiter, authenticateToken, isAdmin, logAdminAction, async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "❌ Invalid user ID" });
    }
    const user = await User.findByIdAndUpdate(
      userId,
      { banned: true },
      { new: true }
    ).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    
    await req.logAudit("BAN_USER", "user", userId, { userEmail: user.email });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ message: "Failed to ban user" });
  }
});

// Edit user
app.put("/api/admin/users/:userId", adminLimiter, authenticateToken, isAdmin, validateInput, logAdminAction, async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "❌ Invalid user ID" });
    }
    
    const { name, email } = req.body;
    if (!name || !email) {
      return res.status(400).json({ message: "❌ Name and email required" });
    }
    
    const user = await User.findByIdAndUpdate(
      userId,
      { name, email },
      { new: true }
    ).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    
    await req.logAudit("UPDATE_USER", "user", userId, { name, email });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ message: "Failed to update user" });
  }
});

// Get all questions
app.get("/api/admin/questions", adminLimiter, authenticateToken, isAdmin, async (req, res) => {
  try {
    const questions = await Question.find();
    res.json(questions);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch questions" });
  }
});

// Add question
app.post("/api/admin/questions", adminLimiter, authenticateToken, isAdmin, validateInput, logAdminAction, async (req, res) => {
  try {
    const { exam, subject, chapter, question, options, answer } = req.body;
    
    // Validation
    if (!exam || !subject || !chapter || !question || !options || typeof answer !== 'string') {
      return res.status(400).json({ message: "❌ Missing required fields" });
    }
    if (!Array.isArray(options) || options.length !== 4) {
      return res.status(400).json({ message: "❌ Must have exactly 4 options" });
    }
    
    const newQuestion = new Question({
      exam,
      subject,
      chapter,
      question,
      options,
      answer
    });
    await newQuestion.save();
    
    await req.logAudit("ADD_QUESTION", "question", newQuestion._id, { exam, subject, chapter });
    res.status(201).json({ success: true, question: newQuestion });
  } catch (err) {
    res.status(500).json({ message: "Failed to add question" });
  }
});

// Edit question
app.put("/api/admin/questions/:questionId", adminLimiter, authenticateToken, isAdmin, validateInput, logAdminAction, async (req, res) => {
  try {
    const questionId = req.params.questionId;
    if (!mongoose.Types.ObjectId.isValid(questionId)) {
      return res.status(400).json({ message: "❌ Invalid question ID" });
    }
    
    const { exam, subject, chapter, question, options, answer } = req.body;
    
    // Validation
    if (!exam || !subject || !chapter || !question || !options || typeof answer !== 'string') {
      return res.status(400).json({ message: "❌ Missing required fields" });
    }
    if (!Array.isArray(options) || options.length !== 4) {
      return res.status(400).json({ message: "❌ Must have exactly 4 options" });
    }
    
    const updatedQuestion = await Question.findByIdAndUpdate(
      questionId,
      {
        exam,
        subject,
        chapter,
        question,
        options,
        answer
      },
      { new: true }
    );
    if (!updatedQuestion) return res.status(404).json({ message: "Question not found" });
    
    await req.logAudit("UPDATE_QUESTION", "question", questionId, { exam, subject });
    res.json({ success: true, question: updatedQuestion });
  } catch (err) {
    res.status(500).json({ message: "Failed to update question" });
  }
});

// Delete question
app.delete("/api/admin/questions/:questionId", adminLimiter, authenticateToken, isAdmin, logAdminAction, async (req, res) => {
  try {
    const questionId = req.params.questionId;
    if (!mongoose.Types.ObjectId.isValid(questionId)) {
      return res.status(400).json({ message: "❌ Invalid question ID" });
    }
    
    const question = await Question.findByIdAndDelete(questionId);
    if (!question) return res.status(404).json({ message: "Question not found" });
    
    await req.logAudit("DELETE_QUESTION", "question", questionId, { exam: question.exam });
    res.json({ success: true, message: "Question deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete question" });
  }
});

// Bulk Upload Questions (10-20 at once)
app.post("/api/questions/bulk", bulkUploadLimiter, authenticateToken, isAdmin, validateInput, logAdminAction, async (req, res) => {
  try {
    const questions = req.body;

    // Validation
    if (!Array.isArray(questions) || questions.length < 10 || questions.length > 20) {
      return res.status(400).json({ message: "❌ Must upload between 10-20 questions" });
    }

    // Validate each question
    for (let i = 0; i < questions.length; i++) {
      const q = questions[i];
      if (!q.exam || !q.subject || !q.chapter || !q.question) {
        return res.status(400).json({ message: `❌ Question ${i + 1}: Missing required fields` });
      }
      if (!Array.isArray(q.options) || q.options.length !== 4) {
        return res.status(400).json({ message: `❌ Question ${i + 1}: Must have exactly 4 options` });
      }
      if (typeof q.answer !== 'string') {
        return res.status(400).json({ message: `❌ Question ${i + 1}: Invalid answer format` });
      }
    }

    // Insert all questions
    const insertedQuestions = await Question.insertMany(questions);
    
    await req.logAudit("BULK_UPLOAD_QUESTIONS", "question", "bulk", { count: insertedQuestions.length });
    
    res.status(201).json({ 
      success: true, 
      message: `Successfully uploaded ${insertedQuestions.length} questions`,
      count: insertedQuestions.length 
    });
  } catch (err) {
    console.error("Bulk upload error:", err);
    res.status(500).json({ message: "Failed to bulk upload questions" });
  }
});

// --- 9. HEALTH CHECK & SETUP ---
app.get("/health", (req, res) => {
  res.json({ 
    success: true, 
    message: "Server is running", 
    timestamp: new Date(),
    database: "Connected",
    port: process.env.PORT || 5000
  });
});

// Create admin user endpoint (for setup)
app.post("/api/create-admin", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "All fields required" });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Email already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const admin = new User({
      name,
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      role: "admin"
    });

    await admin.save();
    const token = generateToken(admin._id);

    res.status(201).json({
      success: true,
      message: "Admin user created successfully",
      user: { _id: admin._id, name: admin.name, email: admin.email, role: admin.role },
      token
    });
  } catch (err) {
    console.error("Admin creation error:", err);
    res.status(500).json({ success: false, message: "Failed to create admin" });
  }
});

const PORT = process.env.PORT || 5000;

// Import notification routes
const notificationRoutes = require('./routes/notification');

// Use notification routes
app.use('/api/notifications', notificationRoutes);

app.listen(PORT, () => console.log(`Secure Server running on port ${PORT}`));