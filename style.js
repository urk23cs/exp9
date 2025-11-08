const User = require('../models/User'); const bcrypt = require('bcryptjs'); const jwt = require('jsonwebtoken');

exports.registerUser = async (req, res) => {
const { full_name, email, username, password, confirm_password } = req.body; if (!full_name || !email || !username || !password || !confirm_password) {
 
return res.status(400).json({ message: 'All fields are required.' });
}
if (password !== confirm_password) {
return res.status(400).json({ message: 'Passwords do not match.' });
}
if (password.length < 6) {
return res.status(400).json({ message: 'Password must be at least 6 characters.' });
}
try {
const existingUser = await User.findOne({ $or: [{ email }, { username }] }); if (existingUser) {
return res.status(400).json({ message: 'Email or Username already exists.' });
}
const salt = await bcrypt.genSalt(10);
const hashedPassword = await bcrypt.hash(password, salt);
const newUser = new User({ full_name, email, username, password: hashedPassword }); await newUser.save();
res.status(201).json({ message: 'User registered successfully!' });
} catch (error) {
console.error('Registration error:', error); // Debug output res.status(500).json({ message: 'Server error.' });
}
};


exports.loginUser = async (req, res) => {
 
const { login, password } = req.body; // login can be username or email if (!login || !password) {
return res.status(400).json({ message: 'Username/Email and password required.' });
}
try {
const user = await User.findOne({ $or: [{ email: login }, { username: login }] }); if (!user) {
return res.status(400).json({ message: 'Invalid credentials.' });
}
const isMatch = await bcrypt.compare(password, user.password); if (!isMatch) {
return res.status(400).json({ message: 'Invalid credentials.' });
}
const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' }); res.cookie('token', token, { httpOnly: true });
res.json({ message: 'Login successful', user: { username: user.username, full_name: user.full_name } });
} catch (error) {
console.error('Login error:', error); // Debug output res.status(500).json({ message: 'Server error.' });
}
;

