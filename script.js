const dns = require('dns');
dns.setServers(['8.8.8.8', '1.1.1.1']);

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Resend } = require('resend');

const app = express();

// 🔹 Middleware
app.use(express.json());
app.use(cors());

// 🔹 Register Route (PASTE HERE)
app.post('/register', async (req, res) => {
    try {
        console.log(req.body);
        res.json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ error: "Server error" });
    }
});

// 🔹 Start Server
app.listen(3000, () => {
    console.log("Server running on port 3000");
});
app.use(express.static('public'));

const resend = new Resend(process.env.RESEND_API_KEY);

// ===================================================
// Connect to MongoDB
// ===================================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log('❌ MongoDB Error:', err));

// ===================================================
// Schemas
// ===================================================
const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  isVerified: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

const otpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  expiresAt: Date
});
const OTP = mongoose.model('OTP', otpSchema);

// ===================================================
// Send OTP Email via Resend
// ===================================================
async function sendOTPEmail(email, otp, username = '') {
  await resend.emails.send({
    from: 'onboarding@resend.dev',
    to: email,
    subject: 'Your MyPodcast OTP Code',
    html: `
      <div style="font-family: Arial; background: #0a0e27; color: white; padding: 40px; border-radius: 20px; max-width: 500px; margin: auto;">
        <h2 style="color: #00d4ff;">MYPODCAST</h2>
        <p style="color: #b0b8cc;">Your one-time password:</p>
        <h1 style="color: #ff006e; font-size: 3rem; letter-spacing: 15px;">${otp}</h1>
        <p style="color: #b0b8cc;">Expires in 10 minutes.</p>
        <p style="color: #b0b8cc;">If you did not request this, ignore this email.</p>
      </div>
    `
  });
}

// ===================================================
// REGISTER
// ===================================================
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.json({ message: 'All fields are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser && existingUser.isVerified) {
      return res.json({ message: 'Email already registered' });
    }

    if (!existingUser) {
      const hashedPassword = await bcrypt.hash(password, 10);
      await User.create({ username, email, password: hashedPassword });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.findOneAndDelete({ email });
    await OTP.create({ email, otp, expiresAt: new Date(Date.now() + 10 * 60 * 1000) });

    try {
      await sendOTPEmail(email, otp, username);
      res.json({ message: 'OTP sent! Check your email to verify your account.', requireOTP: true });
    } catch (emailError) {
      console.error('Email error:', emailError.message);
      res.json({ message: 'Email sending failed. Please try again.', requireOTP: false });
    }

  } catch (error) {
    console.error(error);
    res.json({ message: 'Error registering user' });
  }
});

// ===================================================
// VERIFY REGISTER OTP
// ===================================================
app.post('/verify-register', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const record = await OTP.findOne({ email });

    if (!record) return res.json({ message: 'OTP not found. Please register again.' });
    if (record.expiresAt < new Date()) {
      await OTP.findOneAndDelete({ email });
      return res.json({ message: 'OTP expired. Please register again.' });
    }
    if (record.otp !== otp.toString().trim()) return res.json({ message: 'Incorrect OTP. Try again.' });

    await OTP.findOneAndDelete({ email });
    await User.findOneAndUpdate({ email }, { isVerified: true });

    res.json({ message: 'Email verified successfully! You can now login.' });
  } catch (error) {
    console.error(error);
    res.json({ message: 'Error verifying OTP' });
  }
});

// ===================================================
// SEND LOGIN OTP
// ===================================================
app.post('/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.json({ message: 'Email not registered' });
    if (user.isVerified === false) return res.json({ message: 'Please verify your email first' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.findOneAndDelete({ email });
    await OTP.create({ email, otp, expiresAt: new Date(Date.now() + 10 * 60 * 1000) });

    try {
      await sendOTPEmail(email, otp, user.username);
      res.json({ message: 'OTP sent to your email!' });
    } catch (emailError) {
      console.error('Email error:', emailError.message);
      res.json({ message: 'Email sending failed. Please try again.' });
    }

  } catch (error) {
    console.error(error);
    res.json({ message: 'Error sending OTP' });
  }
});

// ===================================================
// VERIFY LOGIN OTP
// ===================================================
app.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const record = await OTP.findOne({ email });

    if (!record) return res.json({ message: 'OTP not found. Request a new one.' });
    if (record.expiresAt < new Date()) {
      await OTP.findOneAndDelete({ email });
      return res.json({ message: 'OTP expired. Request a new one.' });
    }
    if (record.otp !== otp.toString().trim()) return res.json({ message: 'Incorrect OTP. Try again.' });

    await OTP.findOneAndDelete({ email });
    const user = await User.findOne({ email });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful!', token, username: user.username });

  } catch (error) {
    console.error(error);
    res.json({ message: 'Error verifying OTP' });
  }
});

// ===================================================
// LOGIN WITH PASSWORD
// ===================================================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) return res.json({ message: 'All fields are required' });

    const user = await User.findOne({ email });
    if (!user) return res.json({ message: 'Email not registered' });
    if (user.isVerified === false) return res.json({ message: 'Please verify your email first' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful!', token, username: user.username });
  } catch (error) {
    console.error('Login error:', error);
    res.json({ message: 'Error logging in' });
  }
});

// ===================================================
// TEST ROUTE
// ===================================================
app.get('/test', (req, res) => {
  res.json({
    message: 'Server is working!',
    mongo: mongoose.connection.readyState === 1 ? 'Connected' : 'Not connected',
    env: {
      hasMongoUri: !!process.env.MONGO_URI,
      hasJwtSecret: !!process.env.JWT_SECRET,
      hasResendKey: !!process.env.RESEND_API_KEY
    }
  });
});

// ===================================================

