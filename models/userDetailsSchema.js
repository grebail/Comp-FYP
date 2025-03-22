const mongoose = require('mongoose');

// Loan details schema to align with UserBorrow schema
const loanDetailsSchema = new mongoose.Schema({
    borrowId: { type: mongoose.Schema.Types.ObjectId, ref: 'UserBorrow' },
    details: {
        title: { type: String, required: true },
        authors: { type: [String], required: true },
        publisher: { type: String },
        publishedDate: { type: String },
        industryIdentifier: { type: [String] },
        copies: {
            type: [
                {
                    copyId: { type: String, required: true },
                    bookLocation: { type: String, required: true, enum: ['Stanley Ho Library', 'Ho Sik Yee Library'] },
                    locationId: { type: String, required: true },
                    availability: { type: Boolean, default: true },
                    borrowedDate: { type: Date, default: null },
                    dueDate: { type: Date, default: null },
                    epc: { type: String },
                    status: { type: String, required: true, enum: ['borrowed', 'in return box', 'in library'], default: 'in library' },
                    borrowStatus: { type: Boolean, default: false },
                },
            ],
            required: true,
        },
        comments: {
            type: [
                {
                    rating: { type: Number, min: 1, max: 5, required: true },
                    comment: { type: String },
                    date: { type: Date, default: () => setMidnight(new Date()) },
                },
            ],
            default: [],
        },
        googleId: { type: String },
        returned: { type: Boolean, default: false }, // Indicates whether all copies are returned
    },
});

// Modify the userDetailsSchema to include the new structure for currentLoans


const userDetailsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String },
    email: { type: String },
    phone: { type: String },
    libraryCard: { type: String },
    currentLoans: [loanDetailsSchema], // Reflecting the updated structure
    roomBookings: [{ type: mongoose.Schema.Types.ObjectId, ref: 'RoomBooking' }], // References RoomBooking schema
    eventBookings: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Event' }],
});




const UserDetails = mongoose.model('UserDetails', userDetailsSchema, 'userDetails');
module.exports = UserDetails;