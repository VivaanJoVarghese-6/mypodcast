require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const sgMail = require("@sendgrid/mail");

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// ============================
// MongoDB Connection
// ============================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err));

// ============================
// Schemas
// ============================
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

const User = mongoose.model("User", userSchema);
const OTP = mongoose.model("OTP", otpSchema);

// ============================
// Send OTP Email (SendGrid)
// ============================
async function sendOTPEmail(email, otp) {
  const msg = {
    to: email,
    from: process.env.EMAIL,
    subject: "🔑 Your MyPodcast OTP Code",
    html: `
      <div style="font-family: Arial; background: #0a0e27; color: white; padding: 40px; border-radius: 20px; max-width: 500px; margin: auto;">
        <h2 style="color: #00d4ff;">MYPODCAST 🎙️</h2>
        <p style="color: #b0b8cc;">Your one-time password:</p>
        <h1 style="color: #ff006e; font-size: 3rem; letter-spacing: 15px;">${otp}</h1>
        <p style="color: #b0b8cc;">Expires in 10 minutes.</p>
        <p style="color: #b0b8cc;">If you did not request this, ignore this email.</p>
      </div>
    `
  };
  try {
    await sgMail.send(msg);
    console.log("✅ OTP Sent to", email);
    return true;
  } catch (error) {
    console.error("❌ SendGrid Error:", error.response?.body || error);
    return false;
  }
}

// ============================
// REGISTER
// ============================
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password)
      return res.json({ message: "All fields required" });

    const existingUser = await User.findOne({ email });

    // If user exists and verified → block
    if (existingUser && existingUser.isVerified)
      return res.json({ message: "Email already registered" });

    // If user exists but NOT verified → delete and let them re-register
    if (existingUser && !existingUser.isVerified)
      await User.deleteOne({ email });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, email, password: hashedPassword });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteOne({ email });
    await OTP.create({ email, otp, expiresAt: new Date(Date.now() + 10 * 60 * 1000) });

    const sent = await sendOTPEmail(email, otp);
    if (!sent)
      return res.json({ message: "Failed to send OTP. Please try again." });

    res.json({ message: "OTP sent! Check your email.", requireOTP: true });

  } catch (err) {
    console.error(err);
    res.json({ message: "Register error" });
  }
});

// ============================
// VERIFY REGISTER OTP
// ============================
app.post("/verify-register", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const record = await OTP.findOne({ email });
    if (!record)
      return res.json({ message: "OTP not found. Please register again." });

    if (record.expiresAt < new Date()) {
      await OTP.deleteOne({ email });
      return res.json({ message: "OTP expired. Please register again." });
    }

    if (record.otp !== otp.trim())
      return res.json({ message: "Incorrect OTP. Try again." });

    await OTP.deleteOne({ email });
    await User.updateOne({ email }, { isVerified: true });

    res.json({ message: "Email verified successfully! You can now login. ✅" });

  } catch {
    res.json({ message: "Verification error" });
  }
});

// ============================
// LOGIN WITH PASSWORD
// ============================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.json({ message: "Email not registered" });

    if (user.isVerified === false)
      return res.json({ message: "Please verify your email first" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.json({ message: "Invalid password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Login successful 🎉", token, username: user.username });

  } catch {
    res.json({ message: "Login error" });
  }
});

// ============================
// SEND LOGIN OTP
// (supports both /send-otp and /send-login-otp)
// ============================
async function handleSendOTP(req, res) {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.json({ message: "Email not registered" });

    if (user.isVerified === false)
      return res.json({ message: "Please verify your email first" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteOne({ email });
    await OTP.create({ email, otp, expiresAt: new Date(Date.now() + 10 * 60 * 1000) });

    const sent = await sendOTPEmail(email, otp);
    if (!sent)
      return res.json({ message: "Failed to send OTP. Please try again." });

    res.json({ message: "OTP sent to your email!" });

  } catch (err) {
    console.error(err);
    res.json({ message: "Error sending OTP" });
  }
}

// Both routes point to same function
app.post("/send-otp", handleSendOTP);
app.post("/send-login-otp", handleSendOTP);

// ============================
// VERIFY LOGIN OTP
// (supports both /verify-otp and /verify-login-otp)
// ============================
async function handleVerifyOTP(req, res) {
  try {
    const { email, otp } = req.body;

    const record = await OTP.findOne({ email });
    if (!record)
      return res.json({ message: "OTP not found. Request a new one." });

    if (record.expiresAt < new Date()) {
      await OTP.deleteOne({ email });
      return res.json({ message: "OTP expired. Request a new one." });
    }

    if (record.otp !== otp.trim())
      return res.json({ message: "Incorrect OTP. Try again." });

    await OTP.deleteOne({ email });

    const user = await User.findOne({ email });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({ message: "Login successful 🎉", token, username: user.username });

  } catch (err) {
    console.error(err);
    res.json({ message: "Verification error" });
  }
}

// Both routes point to same function
app.post("/verify-otp", handleVerifyOTP);
app.post("/verify-login-otp", handleVerifyOTP);

// ============================
// PROTECTED ROUTE
// ============================
function verifyToken(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.json({ message: "No token provided" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.json({ message: "Invalid token" });
  }
}

app.get("/dashboard", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json({ message: `Welcome ${user.username} 🎉`, user });
});

// ============================
// TEST ROUTE
// ============================
app.get("/test", (req, res) => {
  res.json({
    message: "Server is working!",
    mongo: mongoose.connection.readyState === 1 ? "Connected" : "Not connected",
    env: {
      hasMongoUri: !!process.env.MONGO_URI,
      hasJwtSecret: !!process.env.JWT_SECRET,
      hasSendGrid: !!process.env.SENDGRID_API_KEY,
      hasEmail: !!process.env.EMAIL
    }
  });
});
app.get('/test-smtp', (req, res) => {
  const net = require('net');
  const ports = [25, 465, 587, 2525];
  const results = [];

  ports.forEach(port => {
    const socket = net.createConnection(port, 'smtp.gmail.com', () => {
      results.push(`✅ Port ${port} — OPEN`);
      socket.destroy();
    });

    socket.setTimeout(5000);
    socket.on('timeout', () => {
      results.push(`❌ Port ${port} — BLOCKED`);
      socket.destroy();
    });
    socket.on('error', (err) => {
      results.push(`❌ Port ${port} — ERROR: ${err.message}`);
    });
  });

  // Wait for all tests then respond
  setTimeout(() => {
    res.json({ results });
  }, 6000);
});

// ============================
// START SERVER
// ============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
