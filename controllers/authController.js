const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createError } = require("../middleware/error");
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");

dotenv.config();

const generateToken = (payload) => {
  const token = jwt.sign(payload, process.env.JWT, { expiresIn: "1h" });
  return token;
};

const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT);
    return decoded;
  } catch (err) {
    throw new Error("Invalid token");
  }
};

// @desc    Register new user
// @route   POST /api/register
// @access  Public
const registerUser = async (req, res, next) => {
  try {
    const salt = await bcrypt.genSalt(10);
    const email = req.body.email;
    const password = req.body.password;
    const hash = await bcrypt.hash(req.body.password, salt);
    let obj = null;

    // Check if the credentials match the admin
    if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
        // Generate a token for the admin
        obj = {...req.body,isAdmin : true, type : "admin"} ;
        console.log(obj);
    }

    obj = {...req.body,type:"traveller"};

    const newUser = new User({
      ...obj,
      password: hash,
    });


    await newUser.save();
    res.status(200).send("User created successfully");
  } catch (error) {
    next(error);
  }
};

// @desc    Login user
// @route   POST /api/login
// @access  Public
const loginUser = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Check the database for normal users
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json("User not found");
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json("Wrong password");
    }

    // Create a token for the regular user
    const token = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT
    );

    const { password: _, isAdmin, ...otherDetails } = user._doc;
    res
      .cookie("access_token", token, {
        httpOnly: true,
      })
      .status(200)
      .json({ details: { ...otherDetails }, isAdmin, token });
  } catch (error) {
    next(error);
  }
};

// @desc    Logout user
// @route   POST /api/logout
// @access  Private
const logoutUser = (req, res) => {
  res.clearCookie("access_token");
  req.session?.destroy();
  res.status(200).send("Logged out successfully");
};

// @desc    Reset password request
// @route   POST /api/reset-password-request
// @access  Public
const resetpasswordrequest = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const token = generateToken({ userId: user._id });
    const resetLink = `http://localhost:3000/reset-password?token=${token}`;

    let transporter = nodemailer.createTransport({
      host: "smtp.office365.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      tls: {
        ciphers: "SSLv3",
      },
    });

    let info = await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Reset Password",
      text: `Please click on the following link to reset your password: ${resetLink}`,
    });

    console.log("Message sent: %s", info.messageId);

    res.json({ message: "Reset password email sent", token: token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// @desc    Reset password
// @route   POST /api/reset-password
// @access  Public
const resetpassword = async (req, res) => {
  const { token, password } = req.body;

  try {
    const { userId } = verifyToken(token);
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    user.password = hash;
    await user.save();

    res.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// @desc    Check if email exists
// @route   GET /api/check-email
// @access  Public
const checkEmailExists = async (req, res, next) => {
  try {
    const { email } = req.query;
    const user = await User.findOne({ email });
    if (user) {
      return res.status(409).json({ message: "Email already exists" });
    }
    return res.status(200).json({ message: "Email is available" });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  resetpasswordrequest,
  resetpassword,
  checkEmailExists,
};
