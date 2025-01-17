const mongoose = require('mongoose');
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
    copies: [{ // Change copyId to an array of objects
        copyId: {
            type: String, // Unique identifier for each copy

        },
        bookLocation: {
            type: String,

        },
        locationId: {
            type: String,

        },
        availability: {
            type: Boolean,

        }
    }],
});

// Create the model based on the schema
const BookBuy = mongoose.model('BookBuy', buyBookSchema, 'purchase_list');

module.exports = BookBuy;