const mongoose = require('mongoose');

// Define the schema for book purchases
const buyBookSchema = new mongoose.Schema({
    userid: {
        type: String,
        required: true,
    },
    googleId: {
        type: String,
        required: true,
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
});

// Create the model based on the schema
const BookBuy = mongoose.model('BookBuy', buyBookSchema, 'purchase_list');

module.exports = BookBuy;