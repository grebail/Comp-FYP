const mongoose = require('mongoose');

const loanDetailsSchema = new mongoose.Schema({
    borrowId: { type: mongoose.Schema.Types.ObjectId, ref: 'UserBorrow' },
    details: {
        title: { type: String },
        authors: { type: [String] },
        availability: { type: Boolean },
        borrowDate: { type: Date },
        dueDate: { type: Date },
        comments: { type: [String], default: [] },
        copyId: { type: [String], default: [] },
        googleId: { type: String},
        industryIdentifier: { type: [String]},
        publishedDate: { type: String },
        publisher: { type: String },
        returned: { type: Boolean }
    }
});

// Modify the userDetailsSchema to include the new structure for currentLoans
const userDetailsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, },
    email: { type: String, },
    phone: { type: String, },
    libraryCard: { type: String},
    currentLoans: [loanDetailsSchema] ,// Updated to store detailed loan information
    roomBookings: [{ type: mongoose.Schema.Types.ObjectId, ref: 'RoomBooking' }]
});

const UserDetails = mongoose.model('UserDetails', userDetailsSchema, 'userDetails'); // Create the UserDetails model
module.exports = UserDetails; // Export the UserDetails model