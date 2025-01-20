const mongoose = require('mongoose');

// Define an enumeration for book locations
const bookLocationEnum = ['Stanley Ho Library', 'Ho Sik Yee Library'];

// Function to set time to midnight
const setMidnight = (date) => {
    const midnightDate = new Date(date);
    midnightDate.setHours(0, 0, 0, 0); // Set hours, minutes, seconds, and milliseconds to 0
    return midnightDate;
};

// Define the schema for book borrowing
const bookBorrowSchema = new mongoose.Schema({
    userid: {
        type: String,
        required: true,
    },
    googleId: {
        type: String,
        required: true,
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
        // Make publisher required
    },
    publishedDate: {
        type: String,
        // Make publishedDate required
    },
    industryIdentifier: {
        type: [String], // Array to store multiple ISBNs
        required: true, // Make this required
    },
    bookLocation: {
        type: String,
        enum: bookLocationEnum, // Use the defined enum
        // Not required
    },
    locationId: {
        type: String, // String to store the LCC code of the book
        // Not required
    },
    availability: {
        type: Boolean,
        default: true, // Default to true, but not required
    },
    noOfCopy: {
        type: Number,

        min: 1, // Ensure at least one copy exists
    },
    copyId: {
        type: [String], // Array to store copy IDs
    },
    borrowDate: {
        type: Date,
        default: () => setMidnight(new Date()), // Automatically set to midnight of the current date
    },
    dueDate: {
        type: Date,
        default: () => {
            const dueDate = new Date();
            dueDate.setMonth(dueDate.getMonth() + 1); // Set due date to one month from now
            return setMidnight(dueDate); // Set to midnight of the due date
        },
    },
    returned: {
        type: Boolean,
        default: false, // Default to false indicating the book is not returned yet
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