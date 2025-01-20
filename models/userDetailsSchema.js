const mongoose = require('mongoose');

const userDetailsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    libraryCard: { type: String, required: true, unique: true }, // Add library card as required
    currentLoans: [{ type: mongoose.Schema.Types.ObjectId, ref: 'UserBorrow' }] // Array to store current loans
});

const UserDetails = mongoose.model('UserDetails', userDetailsSchema, 'userDetails'); // Create the UserDetails model
module.exports = UserDetails; // Export the UserDetails model