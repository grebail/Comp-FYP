const mongoose = require('mongoose');

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
    borrowDate: {
        type: Date,
        default: Date.now, // Automatically set the borrow date to the current date
    },
    dueDate: {
        type: Date,
        default: () => {
            const today = new Date();
            today.setMonth(today.getMonth() + 1); // Set due date to one month from today
            return today;
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
           
        },
        date: {
            type: Date,
            default: Date.now, // Automatically set the date of the comment
        },
    }],
});

// Create the model based on the schema
const BookBorrow = mongoose.model('BookBorrow', bookBorrowSchema, 'userBorrows');

module.exports = BookBorrow;
