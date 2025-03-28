const mongoose = require('mongoose');

const epcSchema = new mongoose.Schema({
    epc: { type: String, required: true, unique: true },
    title: { type: String, required: true },
    author: { type: [String], required: true },
    status: {
        type: String,
        enum: ['borrowed', 'in return box', 'in library'],
        default: 'in return box'
    },
    industryIdentifier: { type: [String] },
    timestamp: { type: Date, default: Date.now },
    readerIp: { type: String },
    logs: [{ message: String, timestamp: Date }]
});

const Epc = mongoose.model('EPC', epcSchema);

const shelfSchema = new mongoose.Schema({
    readerIp: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    connected: { type: Boolean, default: false }
});

const Shelf = mongoose.model('Shelf', shelfSchema);

const returnBoxSchema = new mongoose.Schema({
    readerIp: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    connected: { type: Boolean, default: false }
});

const ReturnBox = mongoose.model('ReturnBox', returnBoxSchema);

module.exports = { Epc, Shelf, ReturnBox };