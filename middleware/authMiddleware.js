const jwt = require('jsonwebtoken');
//normal user
const User = require('../models/userModel.js');
const dotenv = require("dotenv");

dotenv.config();


const userMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies.access_token;
    if (!token) {
      return res.status(401).json({ message: 'Invalid Token' });
    }
    const decoded = jwt.verify(token, process.env.JWT);
    req.user = decoded.id;
    next();
  } catch (err) {
    console.error(err);
    return res.status(401).json({ message: 'Invalid Token' });
  }
};
//admin
const adminMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies.access_token;
    if (!token) {
      return res.status(401).json({ message: 'Invalid Token' });
    }
    const decoded = jwt.verify(token, process.env.JWT);
    const user = await User.findById(decoded.id, { isAdmin: 1 });
    console.log(user);
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    if (!user.isAdmin) {
      return res.status(403).json({ message: 'Access denied' });
    }
    req.user = decoded.id;
    next();
  } catch (err) {
    console.error(err);
    return res.status(401).json({ message: 'Invalid Token' });
  }
};
//activity organizer
const organizerMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies.access_token;
    if (!token) {
      return res.status(401).json({ message: 'Invalid Token' });
    }
    const decoded = jwt.verify(token, processs.env.JWT);
    const user = await User.findById(decoded.id, { type: 1 });
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    if (user.type !== 'eventOrganizer') {
      return res.status(403).json({ message: 'Access denied' });
    }
    req.user = decoded.id;
    next();
  } catch (err) {
    console.error(err);
    return res.status(401).json({ message: 'Invalid Token' });
  }
};

module.exports = {
  userMiddleware,
  adminMiddleware,
  organizerMiddleware,
};
