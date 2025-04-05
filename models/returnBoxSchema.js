const mongoose = require('mongoose');

// ReturnBox schema definition
const returnBoxSchema = new mongoose.Schema({
    readerIp: { type: String, required: true, unique: true }, // Reader IP must be unique and required
    name: { type: String, required: true }, // Return box name is required
    connected: { type: Boolean, default: false } // Default state for connectivity
});

// Export the ReturnBox model
module.exports = mongoose.model('ReturnBox', returnBoxSchema);