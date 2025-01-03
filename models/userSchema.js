// models/userSchema.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    googleId: { type: String, unique: true, sparse: true },
    role: { type: String, enum: ['admin', 'librarian', 'user'], default: 'user' }
});

const User = mongoose.model('User', userSchema,'users'); // Create the User model
module.exports = User; // Export the User model
