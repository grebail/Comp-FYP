const mongoose = require('mongoose');

// Shelf schema definition
const shelfSchema = new mongoose.Schema({
    readerIp: { type: String, required: true, unique: true }, // Reader IP must be unique and required
    name: { type: String, required: true }, // Shelf name is required
    connected: { type: Boolean, default: false } // Default state for connectivity
});

// Export the Shelf model
module.exports = mongoose.model('Shelf', shelfSchema);