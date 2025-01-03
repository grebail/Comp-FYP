// adminBookSchema.js
const mongoose = require('mongoose');

// Define the bookLocation enum
const bookLocationEnum = ['Stanley Ho Library', 'Ho Sik Yee Library'];

const adminBookSchema = new mongoose.Schema({
    googleId: { type: String, required: true },
    bookId: { type: mongoose.Schema.Types.ObjectId, ref: 'Book',  }, // Reference to the Book model
    bookLocation: { type: String, enum: bookLocationEnum, required: true },
    availability: { type: Boolean, default: true }, // true or false
    noOfCopy: { type: Number, required: true, min: 0 }, // Number of copies
});

const AdminBook = mongoose.model('AdminBook', adminBookSchema, 'admin_book');

module.exports = AdminBook; // Export the AdminBook model
