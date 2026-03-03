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
    from: process.env.EMAIL, // must be verified sender
    subject: "Your OTP Code",
    html: `<h2>Your OTP is: ${otp}</h2>`
  };

  try {
    await sgMail.send(msg);
    console.log("✅ OTP Sent");
    return true;
  } catch (error) {
    console.error("❌ SendGrid Error:", error.response?.body || error);
    return false;
  }
}

// ============================
// Root Route
// ============================
app.get("/", (req, res) => {
  res.send("Backend Running 🚀");
});

// ============================
// Register
// ============================
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password)
      return res.json({ message: "All fields required" });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.json({ message: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      username,
      email,
      password: hashedPassword
    });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await OTP.deleteOne({ email });
    await OTP.create({
      email,
      otp,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });

    const sent = await sendOTPEmail(email, otp);

    if (!sent)
      return res.json({ message: "Failed to send OTP" });

    res.json({ message: "OTP sent", requireOTP: true });

  } catch (err) {
    console.error(err);
    res.json({ message: "Register error" });
  }
});

// ============================
// Verify OTP
// ============================
app.post("/verify-register", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const record = await OTP.findOne({ email });
    if (!record)
      return res.json({ message: "OTP not found" });

    if (record.expiresAt < new Date()) {
      await OTP.deleteOne({ email });
      return res.json({ message: "OTP expired" });
    }

    if (record.otp !== otp.trim())
      return res.json({ message: "Incorrect OTP" });

    await OTP.deleteOne({ email });
    await User.updateOne({ email }, { isVerified: true });

    res.json({ message: "Email verified successfully ✅" });

  } catch {
    res.json({ message: "Verification error" });
  }
});

// ============================
// Login
// ============================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.json({ message: "Email not registered" });

    if (!user.isVerified)
      return res.json({ message: "Please verify email first" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.json({ message: "Invalid password" });

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful 🎉",
      token,
      username: user.username
    });

  } catch {
    res.json({ message: "Login error" });
  }
});
// ============================
// Send Login OTP
// ============================
app.post("/send-login-otp", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.json({ message: "Email not registered" });

    if (!user.isVerified)
      return res.json({ message: "Please verify email first" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await OTP.deleteOne({ email });

    await OTP.create({
      email,
      otp,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });

    const sent = await sendOTPEmail(email, otp);
    if (!sent)
      return res.json({ message: "Failed to send OTP" });

    res.json({ message: "Login OTP sent", requireOTP: true });

  } catch (err) {
    console.error(err);
    res.json({ message: "Error sending login OTP" });
  }
});

// ============================
// Protected Route
// ============================
function verifyToken(req, res, next) {
  const token = req.headers.authorization;
  if (!token)
    return res.json({ message: "No token provided" });

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
// Start Server
// ============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
