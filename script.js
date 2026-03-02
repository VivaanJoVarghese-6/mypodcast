const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);
const dns = require('dns');
dns.setServers(['8.8.8.8', '1.1.1.1']);

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// ===================================================
// ✅ MongoDB Connection
// ===================================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log('❌ MongoDB Error:', err));

// ===================================================
// ✅ Schemas
// ===================================================
const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  isVerified: { type: Boolean, default: false }
});

const otpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  expiresAt: Date
});

const User = mongoose.model('User', userSchema);
const OTP = mongoose.model('OTP', otpSchema);

// ===================================================
// ✅ Nodemailer (Gmail App Password)
// ===================================================
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true, // true for 465
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASSWORD
  }
});

// ===================================================
// ✅ Send OTP Email
// ===================================================
async function sendOTPEmail(email, otp) {
  try {
    await resend.emails.send({
      from: 'onboarding@resend.dev', // works immediately
      to: email,
      subject: 'Your OTP Code',
      html: `<h2>Your OTP is: ${otp}</h2>`
    });

    console.log("✅ OTP sent successfully");
  } catch (error) {
    console.error("❌ Email sending failed:", error);
  }
}

// ===================================================
// ✅ Register
// ===================================================
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, email, password: hashedPassword });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await OTP.findOneAndDelete({ email });
    await OTP.create({
      email,
      otp,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });

    // 🔥 DO NOT block response if email fails
    sendOTPEmail(email, otp)
      .then(() => console.log("OTP sent"))
      .catch(err => console.log("Email error:", err));

    res.json({ message: "OTP sent", requireOTP: true });

  } catch (err) {
    console.error(err);
    res.json({ message: "Register error" });
  }
});

// ===================================================
// ✅ Verify Register OTP
// ===================================================
app.post('/verify-register', async (req, res) => {
  try {
    const { email, otp } = req.body;

    const record = await OTP.findOne({ email });
    if (!record)
      return res.json({ message: 'OTP not found. Register again.' });

    if (record.expiresAt < new Date()) {
      await OTP.findOneAndDelete({ email });
      return res.json({ message: 'OTP expired. Register again.' });
    }

    if (record.otp !== otp.toString().trim())
      return res.json({ message: 'Incorrect OTP' });

    await OTP.findOneAndDelete({ email });
    await User.findOneAndUpdate({ email }, { isVerified: true });

    res.json({ message: 'Email verified successfully ✅' });

  } catch {
    res.json({ message: 'Error verifying OTP' });
  }
});

// ===================================================
// ✅ Login
// ===================================================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.json({ message: 'Email not registered' });

    if (!user.isVerified)
      return res.json({ message: 'Please verify your email first' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.json({ message: 'Invalid password' });

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful 🎉',
      token,
      username: user.username
    });

  } catch {
    res.json({ message: 'Error logging in' });
  }
});

// ===================================================
// ✅ Protected Route
// ===================================================
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token)
    return res.json({ message: 'No token provided' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.json({ message: 'Invalid token' });
  }
};

app.get('/dashboard', verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json({ message: `Welcome ${user.username} 🎉`, user });
});

// ===================================================
// ✅ Server (Render Compatible)
// ===================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
// ===================================================

