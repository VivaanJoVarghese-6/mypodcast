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
app.use(express.static('public')); // put your HTML files in /public folder

// ===================================================
// 🔹 Connect to MongoDB
// ===================================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log('❌ MongoDB Error:', err));

// ===================================================
// 🔹 Schemas
// ===================================================
const userSchema = new mongoose.Schema({
  username: String,
  email:    { type: String, unique: true },
  password: String,
  isVerified: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

const otpSchema = new mongoose.Schema({
  email:     String,
  otp:       String,
  expiresAt: Date
});
const OTP = mongoose.model('OTP', otpSchema);

// ===================================================
// 🔹 Nodemailer (Gmail)
// ===================================================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASSWORD  // Gmail App Password
  }
});

// ===================================================
// 🔹 Helper: Send OTP Email
// ===================================================
async function sendOTPEmail(email, otp, username = '') {
  await resend.emails.send({
    from: 'onboarding@resend.dev',
    to: email,
    subject: '🔑 Your MyPodcast OTP Code',
    html: `
      <div style="font-family: Arial; background: #0a0e27; color: white; padding: 40px; border-radius: 20px;">
        <h2 style="color: #00d4ff;">MYPODCAST 🎙️</h2>
        <h1 style="color: #ff006e; letter-spacing: 15px;">${otp}</h1>
        <p style="color: #b0b8cc;">Expires in 10 minutes.</p>
      </div>
    `
  });
}
```

---


// ===================================================
// ================= REGISTER =================
// ===================================================
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.json({ message: 'All fields are required' });
    }

    // Check if already registered but not verified
    const existingUser = await User.findOne({ email });
    if (existingUser && existingUser.isVerified) {
      return res.json({ message: 'Email already registered' });
    }

    // If user exists but not verified, just resend OTP
    if (!existingUser) {
      const hashedPassword = await bcrypt.hash(password, 10);
      await User.create({ username, email, password: hashedPassword });
    }

    // Generate and save OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.findOneAndDelete({ email });
    await OTP.create({ email, otp, expiresAt: new Date(Date.now() + 10 * 60 * 1000) });

    // Try to send email
    try {
      await sendOTPEmail(email, otp);
      res.json({ message: 'OTP sent! Check your email to verify your account.', requireOTP: true });
    } catch (emailError) {
      console.error('Email error:', emailError.message);
      res.json({ message: 'Email sending failed. Please try again or use a different email service.', requireOTP: false });
    }

  } catch (error) {
    console.error(error);
    res.json({ message: 'Error registering user' });
  }
});

// ===================================================
// ================= VERIFY REGISTER OTP =================
// ===================================================
app.post('/verify-register', async (req, res) => {
  try {
   const { email, otp } = req.body;
   const cleanOTP = otp.toString().trim();

    if (!record) return res.json({ message: 'OTP not found. Please register again.' });
    if (record.expiresAt < new Date()) {
      await OTP.findOneAndDelete({ email });
      return res.json({ message: 'OTP expired. Please register again.' });
    }
    if (record.otp !== otp.trim()) return res.json({ message: 'Incorrect OTP. Try again.' });

    await OTP.findOneAndDelete({ email });
    await User.findOneAndUpdate({ email }, { isVerified: true });

    res.json({ message: 'Email verified successfully! You can now login. ✅' });
  } catch (error) {
    res.json({ message: 'Error verifying OTP' });
  }
});

// ===================================================
// ================= SEND LOGIN OTP =================
// ===================================================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log('=== LOGIN DEBUG ===');
    console.log('Email:', email);
    console.log('Password received:', password);

    const user = await User.findOne({ email });
    console.log('User found:', user ? 'YES' : 'NO');
    
    if (user) {
      console.log('isVerified:', user.isVerified);
      console.log('Hashed password in DB:', user.password);
    }

    if (!user) return res.json({ message: 'Email not registered' });
    if (user.isVerified === false) return res.json({ message: 'Please verify your email first' });

    const isMatch = await bcrypt.compare(password, user.password);
    console.log('Password match:', isMatch);
    console.log('==================');

    if (!isMatch) return res.json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful 🎉', token, username: user.username });
  } catch (error) {
    console.error('Login error:', error);
    res.json({ message: 'Error logging in' });
  }
});
// ===================================================
// ================= VERIFY LOGIN OTP =================
// ===================================================
app.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    console.log('=== OTP DEBUG ===');
    console.log('Email:', email);
    console.log('OTP from user:', otp);
    console.log('OTP type:', typeof otp);

    const record = await OTP.findOne({ email });
    console.log('OTP record found:', record ? 'YES' : 'NO');
    if (record) {
      console.log('OTP in DB:', record.otp);
      console.log('Expires at:', record.expiresAt);
      console.log('Expired?', record.expiresAt < new Date());
    }
    console.log('=================');

    if (!record) return res.json({ message: 'OTP not found. Request a new one.' });
    if (record.expiresAt < new Date()) {
      await OTP.findOneAndDelete({ email });
      return res.json({ message: 'OTP expired. Request a new one.' });
    }
    if (record.otp !== otp.toString().trim()) return res.json({ message: 'Incorrect OTP. Try again.' });

    await OTP.findOneAndDelete({ email });
    const user = await User.findOne({ email });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful 🎉', token, username: user.username });

  } catch (error) {
    console.error(error);
    res.json({ message: 'Error verifying OTP' });
  }
});
// ===================================================
// ================= LOGIN (password) =================
// ===================================================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.json({ message: 'Email not registered' });
    if (!user.isVerified) return res.json({ message: 'Please verify your email first' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful 🎉', token, username: user.username });
  } catch (error) {
    res.json({ message: 'Error logging in' });
  }
});

// ===================================================
// ================= PROTECTED ROUTE =================
// ===================================================
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.json({ message: 'No token provided' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.json({ message: 'Invalid token' });
  }
};

// Temporary test route
app.get('/send-otp-test', async (req, res) => {
  const email = req.query.email;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.json({ message: 'Email not registered' });
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.findOneAndDelete({ email });
    await OTP.create({ email, otp, expiresAt: new Date(Date.now() + 10 * 60 * 1000) });
    await sendOTPEmail(email, otp);
    
    res.json({ message: 'OTP sent!' });
  } catch(err) {
    res.json({ error: err.message });
  }
});
// ===================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
