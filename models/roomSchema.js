const mongoose = require('mongoose');

// Room Booking Schema
const roomBookingSchema = new mongoose.Schema({
    bookingId: {
        type: String, // Unique Booking ID
        required: true,
    },
    roomName: {
        type: String, // Room Name
        required: true,
    },
    date: {
        type: Date, // Booking Date
        required: true,
    },
    timeslot: {
        type: String, // Timeslot (e.g., "09:00–10:00")
        required: true,
    },
    userEmail: {
        type: String, // Email of the user
        required: true,
    },
    username: {
        type: String, // Name of the user
        required: true,
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId, // Link to UserDetails schema
        ref: 'UserDetails',
        required: true,
    },
});

// Create the RoomBooking model
const RoomBooking = mongoose.model('RoomBooking', roomBookingSchema, 'roomBookings'); // Save in the 'roomBookings' collection

module.exports = RoomBooking; // Export the RoomBooking model