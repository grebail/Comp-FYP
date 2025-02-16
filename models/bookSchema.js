// bookSchema.js
const mongoose = require('mongoose');

const bookSchema = new mongoose.Schema({
    googleId: { type: String,  required: true },
    industryIdentifier: { type: String, unique: true, sparse: true },
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
});

const Book = mongoose.model('Book', bookSchema, 'books');

module.exports = Book; // Export the Book model
