// models/userBorrowSchema.js
const mongoose = require('mongoose');

const userBorrowSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
    googleId: { type: String, required: true },
    borrowedAt: { type: Date, default: Date.now },
    returnDate: { type: Date, required: true }
});

const UserBorrow = mongoose.model('UserBorrow', userBorrowSchema, 'userBorrows');
module.exports = UserBorrow;
