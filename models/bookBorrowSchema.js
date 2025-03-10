const mongoose = require('mongoose');

// Define an enumeration for book locations
const bookLocationEnum = ['Stanley Ho Library', 'Ho Sik Yee Library'];

// Define an enumeration for book statuses
const bookStatusEnum = ['borrowed', 'in return box', 'in library'];

// Function to set time to midnight
const setMidnight = (date) => {
    const midnightDate = new Date(date);
    midnightDate.setHours(0, 0, 0, 0); // Set hours, minutes, seconds, and milliseconds to 0
    return midnightDate;
};

// Define the schema for individual copies
const borrowedCopySchema = new mongoose.Schema({
    copyId: {
        type: String, // Unique identifier for the copy
        required: true,
    },
    bookLocation: {
        type: String,
        enum: bookLocationEnum, // Use the defined enum for book locations
        required: true,
    },
    locationId: {
        type: String, // Identifier for the specific location within the library
        required: true,
    },
    availability: {
        type: Boolean,
        default: true, // Default to true, indicating the copy is available
    },
    borrowedDate: {
        type: Date,
        default: null, // Set to null when the book is not borrowed
    },
    dueDate: {
        type: Date,
        default: null, // Set to null when the book is not borrowed
    },
    epc: {
        type: String, // EPC number from the RFID tag
    },
    status: {
        type: String,
        enum: bookStatusEnum, // Use the defined enum for statuses
        default: 'in library', // Default to 'in library'
    },
    borrowStatus: {
        type: Boolean, // Boolean indicating if the book is borrowed
        default: false, // Default to false (not borrowed)
    },
});

// Define the schema for book borrowing
const bookBorrowSchema = new mongoose.Schema({
    userid: {
        type: mongoose.Schema.Types.ObjectId, // Reference the User schema
        ref: 'User', // Link to the User model
        required: true,
    },
    googleId: {
        type: String,
        required: false, // Updated to optional
    },
    title: {
        type: String,
        required: true, // Make title required
    },
    authors: {
        type: [String],
        required: true, // Make authors required
    },
    publisher: {
        type: String,
    },
    publishedDate: {
        type: String,
    },
    industryIdentifier: {
        type: [String], // Array to store multiple ISBNs
    },
    copies: {
        type: [borrowedCopySchema], // Array of sub-documents for individual copies
        required: true, // At least one copy must exist
    },
    comments: [{
        rating: {
            type: Number,
            min: 1,
            max: 5,
            required: true, // Ensure a rating is provided
        },
        comment: {
            type: String,
            required: false, // Optional comment
        },
        date: {
            type: Date,
            default: () => setMidnight(new Date()), // Automatically set to midnight of the current date
        },
    }],
});

// Create the model based on the schema
const UserBorrow = mongoose.model('UserBorrow', bookBorrowSchema, 'userBorrows');
module.exports = UserBorrow;