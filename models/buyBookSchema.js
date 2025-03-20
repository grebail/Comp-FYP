const mongoose = require('mongoose');

// Define an enumeration for book statuses
const bookStatusEnum = ['borrowed', 'in return box', 'in library'];

// Define the schema for book purchases
const buyBookSchema = new mongoose.Schema({
    userid: {
        type: String,
    },
    googleId: {
        type: String,
    },
    industryIdentifier: {
        type: [String],
    },
    title: String,
    subtitle: String,
    authors: [String],
    publisher: String,
    publishedDate: String,
    description: String,
    pageCount: Number,
    categories: [String],
    language: String,
    coverImage: String,
    smallThumbnail: String,
    infoLink: String,
    saleInfo: Object,
    accessInfo: Object,
    searchInfo: Object,
    previewLink: String,
    purchaseDate: {
        type: Date,
        default: Date.now, // Automatically set the purchase date to the current date
    },
    quantity: {
        type: Number, // Total quantity of the book
        default: 0, // Default to 0 if not specified
    },
    copies: [{ // Array of objects to store details about each copy
        copyId: {
            type: String, // Unique identifier for each copy
        },
        bookLocation: {
            type: String, // Location of the book's copy
        },
        locationId: {
            type: String, // Identifier for the specific location within the library or storage
        },
        availability: {
            type: Boolean, // Indicates whether the copy is available
            default: true, // Default to true (available)
        },
        status: {
            type: String,
            enum: bookStatusEnum, // Use the defined enum for statuses
            default: 'in library', // Default to 'in library'
        },
        epc: {
            type: String, // EPC number from the RFID tag
        },
    }],
});

// Create the model based on the schema
const BookBuy = mongoose.model('BookBuy', buyBookSchema, 'purchase_list');

module.exports = BookBuy;