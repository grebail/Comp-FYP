const mongoose = require('mongoose');

// Define the bookLocation enum
const bookLocationEnum = ['Stanley Ho Library', 'Ho Sik Yee Library'];

const adminBookSchema = new mongoose.Schema({
    industryIdentifier: {
        type: [String], // Array to store multiple ISBNs
        required: true, // Make this required
    },
    googleId: { type: String },
    bookLocation: { type: String, enum: bookLocationEnum, required: true },
    locationId: { type: String }, // String to store the LCC code of the book
    availability: { type: Boolean, default: true }, // true or false
    noOfCopy: { type: Number, required: true, min: 1 }, // Number of copies
    title: { type: String, }, // New field for book title
    author: { type: String, }, // New field for book author
    publishedDate: { type: Date }, // New field for published date
    categories: { type: [String], default: [] }
});

const AdminBook = mongoose.model('AdminBook', adminBookSchema, 'admin_book');

module.exports = AdminBook; // Export the AdminBook model