const mongoose = require('mongoose');

// Define the bookLocation enum
const bookLocationEnum = ['Stanley Ho Library', 'Ho Sik Yee Library'];

const adminBookSchema = new mongoose.Schema({
    googleId: { type: String, required: true },
    copyId: { type: mongoose.Schema.Types.ObjectId }, // ObjectId to identify the book copy
    bookLocation: { type: String, enum: bookLocationEnum, required: true },
    locationId: { type: String }, // String to store the LCC code of the book
    availability: { type: Boolean, default: true }, // true or false
    noOfCopy: { type: Number, required: true, min: 1 }, // Number of copies
});

const AdminBook = mongoose.model('AdminBook', adminBookSchema, 'admin_book');

module.exports = AdminBook; // Export the AdminBook model
