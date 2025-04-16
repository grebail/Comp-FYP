const mongoose = require('mongoose');

// EPC schema definition
const epcSchema = new mongoose.Schema({
    epc: { type: String, required: true, unique: true }, // EPC must be unique and required
    title: { type: String, required: true }, // Book title is required
    author: { type: [String], required: true }, // Author is an array of strings and required
    status: { 
        type: String, 
        enum: ['borrowed', 'in return box', 'in library'], // Restrict to these values
        default: 'in library'
    }, industryIdentifier: {
        type: [String],
    },
    timestamp: { type: Date, default: Date.now },
    readerIp: { type: String, default: null },
    logs: [{
    message: String,
    timestamp: { type: Number, default: Date.now }
  }]
});

// Export the EPC model
module.exports = mongoose.model('EPC', epcSchema);