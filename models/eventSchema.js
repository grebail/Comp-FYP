const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

// Event Schema
const EventSchema = new mongoose.Schema({
    eventId: {
        type: String,
        unique: true, // Enforces unique value
    },
    title: {
        type: String,
        required: true,
    },
    venue: {
        type: String,
        required: true,
    },
    time: {
        type: Date, // The `time` field will store a valid Date object
        required: true,
    },
    eventLink: {
        type: String,
        required: true,
    },
    registeredUsers: {
        type: Map,
        of: String, // Map where the key is the email, and the value is the username
        default: {},
    },
});

// Middleware to preprocess the `time` field
EventSchema.pre('validate', function (next) {
    if (!this.eventId) {
        this.eventId = uuidv4(); // Generate a unique eventId
    }

    // Check if `time` is a string
    if (typeof this.time === 'string') {
        const [startTime] = this.time.split(' - '); // Extract the portion before " - "
        const parsedDate = new Date(startTime); // Convert to Date object

        if (isNaN(parsedDate)) {
            return next(new Error(`Invalid date format for time: "${this.time}"`));
        }

        this.time = parsedDate; // Assign the parsed Date object to the `time` field
    }

    next(); // Proceed to the next middleware
});

// Create and export the Event model
const Event = mongoose.model('Event', EventSchema);
module.exports = Event;