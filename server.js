const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const multer = require('multer');
const net = require('net');
const xlsx = require('xlsx');

const stripBomStream = require('strip-bom-stream');
const fs = require('fs');
const csv = require('csv-parser');

require('dotenv').config();

const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const cron = require('node-cron');
const base64url = require('base64-url');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const OAuth2 = google.auth.OAuth2;

const Book = require('./models/bookSchema');
const User = require('./models/userSchema');
const UserBorrow = require('./models/bookBorrowSchema');
const Comment = require('./models/commentSchema');
const AdminBook = require('./models/adminBookSchema');
const BookBuy = require('./models/buyBookSchema');
const UserDetails = require('./models/userDetailsSchema');
const EPC  = require('./models/epcSchema');
const Shelf = require('./models/shelfSchema');
const ReturnBox = require('./models/returnBoxSchema');

const Event = require('./models/eventSchema');



const RoomBooking = require('./models/roomSchema');
const app = express();
const PORT = process.env.PORT || 10000
const SECRET_KEY = 'your_secure_secret_key';

// Middleware
app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Express session setup
app.use(session({
    secret: 'your_session_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
const mongoURI = "mongodb+srv://Admin:admin@library.8bgvj.mongodb.net/bookManagement?retryWrites=true&w=majority&appName=Library";
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));


app.use(session({
        secret: 'your_secret_key',
        resave: false,
        saveUninitialized: false
    }));



// Serve the "uploads" folder as static content
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// API route to create an EPC
app.post('/api/epc', async (req, res) => {
    try {
        const { epc, title, author, status, industryIdentifier  } = req.body;

        // Create a new EPC record
        const newEPC = new EPC({
            epc,
            title,
            author,
            status,
            industryIdentifier,
        });

        // Save the EPC to the database
        const savedEPC = await newEPC.save();

        res.status(201).json(savedEPC); // Respond with the saved EPC record
    } catch (error) {
        console.error('Error creating EPC:', error); // Log the error details
        res.status(500).json({ error: 'Failed to create EPC.', details: error.message });
    }
});

// Create OAuth2 client with hard-coded credentials
const oauth2Client = new OAuth2(
    '196205826526-a5i6cv0vp224tndtobsbep676cn537hm.apps.googleusercontent.com',       // Replace with your Client ID
    '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',   // Replace with your Client Secret
    'https://developers.google.com/oauthplayground'
);
const scopes = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly',
     // Scope for sending email

    // Add other scopes as needed
];
const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes, // Include the defined scopes
});

console.log('Authorize this app by visiting this url:', authUrl);
// Function to set refresh token and get access token
async function getAccessToken() {
    // Replace with logic to fetch and set the refresh token
    oauth2Client.setCredentials({
        refresh_token: '1//04t2NpS9k9vy_CgYIARAAGAQSNwF-L9Ir5SWysiyTCHoK6ZKYzFdnBI4Onm4-hpR0y_MdtNIZEVZePQE-sHPZpRbsUoT4ld7_hMk' // Replace with your Refresh Token
    });

    // Get access token
    try {
        const { token } = await oauth2Client.getAccessToken();
        if (!token) {
            throw new Error('Failed to obtain access token.');
        }
        return token;
    } catch (error) {
        console.error('Error getting access token:', error);
        throw error; // Re-throw to handle it upstream
    }
}
//evening booking email api
// Function to send booking confirmation email 
async function sendBookingConfirmationEmail(bookingDetails) {
    try {
        const { eventName, userName, userEmail } = bookingDetails;

        if (!userName || !userEmail || !eventName) {
            throw new Error('Missing booking details.');
        }

        const fromAddress = 'abbichiu@gmail.com'; // Replace with your verified email
        const toAddress = userEmail;

        const emailContent = `
Hello ${userName},

Thank you for booking the event "${eventName}" with us!

We are excited to have you join us. Here are the event details:

Event: ${eventName}

Please contact us if you have any questions.

Best regards,
Smart Library Team`;

        const msg = {
            to: toAddress,
            from: fromAddress,
            subject: `Booking Confirmation: ${eventName}`,
            text: emailContent, // Send as plain text
        };

        console.log('Sending email with the following details:', msg);

        const response = await sgMail.send(msg);
        console.log('Email sent successfully. SendGrid response:', response[0].statusCode, response[0].headers);

        return response;
    } catch (error) {
        console.error('Error sending booking confirmation email:', error.response ? error.response.body : error.message);
        throw new Error('Error sending booking confirmation email');
    }
}
 
// API to handle event booking
// API to handle event booking
app.post('/api/bookEvent', async (req, res) => {
    try {
        const { eventName, userId } = req.body;

        // Validate inputs
        if (!eventName || !userId) {
            return res.status(400).json({ error: 'Missing booking details.' });
        }

        console.log(`Searching for event: ${eventName}`);

        // Find the event in the database
        const event = await Event.findOne({ title: eventName });
        if (!event) {
            return res.status(404).json({ error: 'Event not found.' });
        }

        // Ensure `registeredUsers` is a Map
        if (!event.registeredUsers || !(event.registeredUsers instanceof Map)) {
            event.registeredUsers = new Map();
        }

        // Fetch the user's details using the userId
        const userDetails = await UserDetails.findOne({ userId });
        if (!userDetails) {
            return res.status(404).json({ error: 'User details not found. Please register the user first.' });
        }

        const userName = userDetails.name; // Assuming `name` is a field in UserDetails
        const userEmail = userDetails.email; // Assuming `email` is a field in UserDetails

        // Sanitize the email address to use as a key in the Map
        const sanitizedEmail = userEmail.replace(/\./g, '[dot]');

        // Check if the user is already registered
        if (event.registeredUsers.has(sanitizedEmail)) {
            return res.status(400).json({ error: 'User already registered for this event.' });
        }

        // Add the sanitized email and user name to the `registeredUsers` map
        event.registeredUsers.set(sanitizedEmail, userName);
        await event.save();

        console.log(`User ${userName} successfully registered for event ${event.title}`);

        // Add the event to the user's bookings if not already present
        if (!userDetails.eventBookings.includes(event._id)) {
            userDetails.eventBookings.push(event._id);
            await userDetails.save();
        }

        // Send booking confirmation email
        await sendBookingConfirmationEmail({ eventName, userName, userEmail });

        res.status(200).json({
            message: `Booking confirmed for "${eventName}". A confirmation email has been sent to: ${userEmail}`,
        });
    } catch (error) {
        console.error('Error booking event:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// API to fetch all registered users for each event
app.get('/api/events', async (req, res) => {
    try {
        // Fetch all events from the database
        const events = await Event.find({});

        // Map the event data to include all necessary fields
        const eventData = events.map(event => {
            // Convert the registeredUsers map to a regular object for easy handling
            const registeredUsers = {};
            for (const [email, name] of event.registeredUsers.entries()) {
                registeredUsers[email.replace(/\[dot\]/g, '.')] = name; // Replace '[dot]' back to '.'
            }

            return {
                eventId: event.eventId,
                title: event.title,
                venue: event.venue,
                time: event.time,
                description: event.description, // Include description
                image: event.image, // Include image filename
                registeredUsers, // Object with emails as keys and user names as values
            };
        });

        // Send the formatted event data as a JSON response
        res.status(200).json(eventData);
    } catch (error) {
        console.error('Error fetching events:', error.message);
        res.status(500).json({ error: 'Internal server error while fetching events.' });
    }
});



// Configure multer for file uploads
const upload = multer({ dest: 'uploads/' }); // Files will be stored in the "uploads" directory

// API to create a new event
app.post('/api/events', upload.single('image'), async (req, res) => {
    try {
        const { title, description, time, venue } = req.body;

        // Validate required fields
        if (!title || !description || !time || !venue || !req.file) {
            return res.status(400).json({ error: 'All fields are required: title, description, time, venue, and image.' });
        }

        // Create a new event object
        const newEvent = new Event({
            title,
            description,
            time: new Date(time), // Convert to Date object
            venue,
            image: req.file.filename, // Save the uploaded image filename
        });

        // Save the event to the database
        await newEvent.save();

        res.status(201).json({ message: 'Event created successfully!', event: newEvent });
    } catch (error) {
        console.error('Error creating event:', error.message);
        res.status(500).json({ error: 'An error occurred while creating the event.' });
    }
});



// API to edit an event time
app.put('/api/events/:id', async (req, res) => {
    try {
        const { time } = req.body;

        if (!time) {
            return res.status(400).json({ error: 'Event time is required.' });
        }

        // Find and update the event time
        const updatedEvent = await Event.findOneAndUpdate(
            { eventId: req.params.id },
            { time: new Date(time) }, // Convert to Date object
            { new: true }
        );

        if (!updatedEvent) {
            return res.status(404).json({ error: 'Event not found.' });
        }

        res.status(200).json({ message: 'Event time updated successfully!', event: updatedEvent });
    } catch (error) {
        console.error('Error editing event:', error.message);
        res.status(500).json({ error: 'An error occurred while editing the event.' });
    }
});

// API to delete an event
app.delete('/api/events/:id', async (req, res) => {
    try {
        const deletedEvent = await Event.findOneAndDelete({ eventId: req.params.id });

        if (!deletedEvent) {
            return res.status(404).json({ error: 'Event not found.' });
        }

        res.status(200).json({ message: 'Event deleted successfully!' });
    } catch (error) {
        console.error('Error deleting event:', error.message);
        res.status(500).json({ error: 'An error occurred while deleting the event.' });
    }
});

// API to delete expired events
app.delete('/api/deleteExpiredEvents', async (req, res) => {
    try {
        const now = new Date();

        // Delete all events where the time has passed
        const result = await Event.deleteMany({ time: { $lt: now } });

        res.status(200).json({
            message: 'Expired events deleted successfully!',
            deletedCount: result.deletedCount,
        });
    } catch (error) {
        console.error('Error deleting expired events:', error.message);
        res.status(500).json({ error: 'An error occurred while deleting expired events.' });
    }
});

// API to get registered users for an event
app.get('/api/events/:id/registered-users', async (req, res) => {
    try {
        const event = await Event.findOne({ eventId: req.params.id });

        if (!event) {
            return res.status(404).json({ error: 'Event not found.' });
        }

        const registeredUsers = Array.from(event.registeredUsers.entries()).map(([email, name]) => ({ email, name }));

        res.status(200).json({ registeredUsers });
    } catch (error) {
        console.error('Error fetching registered users:', error.message);
        res.status(500).json({ error: 'An error occurred while fetching registered users.' });
    }
});
// Function to send room booking confirmation email
async function sendRoomBookingConfirmationEmail(bookingDetails) {
    try {
        const { roomName, userName, userEmail, date, timeslot } = bookingDetails;

        if (!userName || !userEmail || !roomName || !date || !timeslot) {
            throw new Error('Missing booking details.');
        }

        const fromAddress = 'abbichiu@gmail.com'; // Replace with your verified email
        const toAddress = userEmail;

        const emailContent = `
Hello ${userName},

Thank you for booking the room "${roomName}" with us!

Here are the booking details:

Room: ${roomName}
Date: ${date}
Timeslot: ${timeslot}

We look forward to having you use our facilities. If you have any questions, please feel free to contact us.

Best regards,
Smart Library Team`;

        const msg = {
            to: toAddress,
            from: fromAddress,
            subject: `Booking Confirmation: ${roomName}`,
            text: emailContent, // Send as plain text
        };

        console.log('Sending email with the following details:', msg);

        const response = await sgMail.send(msg);
        console.log('Email sent successfully. SendGrid response:', response[0].statusCode, response[0].headers);

        return response;
    } catch (error) {
        console.error('Error sending room booking confirmation email:', error.response ? error.response.body : error.message);
        throw new Error('Error sending room booking confirmation email');
    }
}
// API to book a room
// API to book a room
app.post('/api/bookRoom', async (req, res) => {
    try {
        const { roomName, date, timeslot, userId } = req.body;

        // Validate inputs
        if (!roomName || !date || !timeslot || !userId) {
            return res.status(400).json({ error: 'Missing booking details.' });
        }

        // Validate user
        const user = await UserDetails.findOne({ userId });
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // Check if the room is already booked for the selected date and timeslot
        const existingBooking = await RoomBooking.findOne({ roomName, date, timeslot });
        if (existingBooking) {
            return res.status(400).json({ error: 'Room is already booked for this timeslot.' });
        }

        // Generate a unique booking ID
        const bookingId = `BOOK-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

        // Create the booking
        const newBooking = new RoomBooking({
            bookingId,
            roomName,
            date,
            timeslot,
            userEmail: user.email,
            username: user.name,
            userId: user._id,
        });

        await newBooking.save();

        // Add the booking to the user's `roomBookings`
        if (!user.roomBookings.includes(newBooking._id)) {
            user.roomBookings.push(newBooking._id);
            await user.save();
        }

        console.log(`Room "${roomName}" booked successfully by user "${user.name}" for ${date} at ${timeslot}.`);

        // Send confirmation email
        const emailDetails = {
            roomName,
            userName: user.name,
            userEmail: user.email,
            date,
            timeslot,
        };

        await sendRoomBookingConfirmationEmail(emailDetails);

        res.status(201).json({ message: 'Room booked successfully', bookingId });
    } catch (error) {
        console.error('Error booking room:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});




// API to fetch user's room bookings
app.get('/api/userBookings', async (req, res) => {
    try {
        const { userId } = req.query;

        // Validate the input
        if (!userId) {
            return res.status(400).json({ error: 'User ID is required.' });
        }

        // Validate user
        const user = await UserDetails.findOne({ userId }).populate({
            path: 'roomBookings',
            select: 'bookingId roomName date timeslot userEmail username',
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // If no room bookings found, return an empty array
        if (!user.roomBookings || user.roomBookings.length === 0) {
            return res.status(200).json({ bookings: [] });
        }

        res.status(200).json({ bookings: user.roomBookings });
    } catch (error) {
        console.error('Error fetching user bookings:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// to fetach all users booking
app.get('/api/bookings', async (req, res) => {
    const bookings = await RoomBooking.find();
    res.json(bookings);
    
});
//librarian to edit booking
app.put('/api/bookings/:id', async (req, res) => {
    const { date, timeslot } = req.body;
    await RoomBooking.findByIdAndUpdate(req.params.id, { date, timeslot });
    res.json({ message: 'Booking updated successfully' });
});
//librarian to delete booking
app.delete('/api/bookings/:id', async (req, res) => {
    await RoomBooking.findByIdAndDelete(req.params.id);
    res.json({ message: 'Booking deleted successfully' });
});
// Delete expired bookings
app.delete('/api/bookings/expired', async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0]; // Get today's date in YYYY-MM-DD format
        const result = await RoomBooking.deleteMany({ date: { $lt: today } }); // Delete bookings with a date earlier than today
        res.json({ message: `${result.deletedCount} expired bookings deleted successfully.` });
    } catch (error) {
        console.error('Error deleting expired bookings:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Function to send email using SendGrid
// Function to send email using SendGrid
async function sendEmail(userDetails, upcomingLoans) {
    try {
        const fromAddress = 'abbichiu@gmail.com'; // Sender email
        const toAddress = userDetails.email;     // Recipient email

        if (!toAddress) {
            throw new Error(`Recipient email address is required for user ${userDetails.name || 'Unknown'}.`);
        }

        // Compose the email content with the upcoming loan details
        let loanDetailsText = 'Loans Due Soon:\n\n';
        upcomingLoans.forEach((loan, index) => {
            loanDetailsText += `Loan ${index + 1}:\n`;
            loanDetailsText += `- Title: ${loan.details.title || 'N/A'}\n`;
            loanDetailsText += `- Authors: ${loan.details.authors ? loan.details.authors.join(', ') : 'N/A'}\n`;
            loanDetailsText += `- Publisher: ${loan.details.publisher || 'N/A'}\n`;
            loanDetailsText += `- Due Date: ${formatDateToUTC(loan.copy.dueDate)}\n\n`;
        });

        const emailContent = `
Hello ${userDetails.name || 'User'},

Here are your loan details that are due soon:

${loanDetailsText}

Please make sure to return the items on time to avoid any penalties.

Best regards,  
Library Team`;

        // Create the email object for SendGrid
        const msg = {
            to: toAddress,
            from: fromAddress,
            subject: 'Loan Due Reminder: Upcoming Loan Details',
            text: emailContent, // Plain text content
            html: `<pre>${emailContent}</pre>`, // HTML content
        };

        // Send email using SendGrid
        const response = await sgMail.send(msg);

        console.log(`Email sent successfully to ${toAddress}. Response:`, response);
        return response; // Return SendGrid response for further processing
    } catch (error) {
        console.error(`Error sending email to ${userDetails.email || 'Unknown Email'}:`, error.message);
        throw error; // Propagate the error
    }
}

// Helper function to format dates to UTC
function formatDateToUTC(date) {
    const utcDate = new Date(date);
    return utcDate.toUTCString(); // Format date in UTC
}
// Route to manually send reminder emails
// Route to manually send reminder emails
app.post('/send-reminder-emails', async (req, res) => {
    try {
        // Force UTC dates
        const today = new Date(new Date().toISOString());
        const threeDaysFromNow = new Date(today);
        threeDaysFromNow.setUTCDate(today.getUTCDate() + 4); // Add 4 days
        threeDaysFromNow.setUTCHours(23, 59, 59, 999); // Set to the end of the fourth day

        console.log('Today (UTC):', today.toISOString());
        console.log('Three Days from Now (UTC, End of Day):', threeDaysFromNow.toISOString());

        // Fetch users with loans having copies due within the next 3 days
        const usersWithLoans = await UserDetails.find({
            currentLoans: {
                $elemMatch: {
                    'details.copies': {
                        $elemMatch: {
                            dueDate: {
                                $gte: today.toISOString(), // Start of the range (inclusive)
                                $lt: threeDaysFromNow.toISOString(), // End of the range (inclusive)
                            },
                        },
                    },
                },
            },
        });

        if (usersWithLoans.length === 0) {
            console.log('No users with loans due in the next 3 days.');
            return res.status(404).json({ message: 'No users with loans due in the next 3 days.' });
        }

        const emailResults = []; // To store the results of email sending

        for (const user of usersWithLoans) {
            if (!user.email) {
                console.error(`User ${user.name || 'Unknown'} is missing an email address.`);
                continue; // Skip users without an email
            }

            // Collect copies due within the next 3 days
            const upcomingLoans = [];
            user.currentLoans.forEach(loan => {
                loan.details.copies.forEach(copy => {
                    const dueDate = new Date(copy.dueDate);
                    if (dueDate >= today && dueDate < threeDaysFromNow) {
                        upcomingLoans.push({ details: loan.details, copy });
                    }
                });
            });

            if (upcomingLoans.length > 0) {
                try {
                    const sendResult = await sendEmail(user, upcomingLoans); // Send email
                    emailResults.push({
                        user: user.name || 'Unknown User',
                        email: user.email,
                        status: 'Success',
                        sendGridResponse: sendResult,
                    });
                } catch (error) {
                    emailResults.push({
                        user: user.name || 'Unknown User',
                        email: user.email,
                        status: 'Failed',
                        error: error.message,
                    });
                }
            }
        }

        // Return the results of the email sending process
        res.status(200).json({
            message: 'Reminder emails processed successfully!',
            emailResults: emailResults,
        });
    } catch (error) {
        console.error('Error sending reminder emails:', error.message);
        res.status(500).json({ error: 'Error sending reminder emails.' });
    }
});
// Assuming you have your Book model defined
const countBooks = async() => {
    try {
        const totalBooks = await Book.countDocuments(); // or Book.count()
        console.log(`Total number of books: ${totalBooks}`);
    } catch (error) {
        console.error('Error counting books:', error);
    }
};

// Call the function
countBooks();




// middleware of token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        console.log('No token provided');
        return res.sendStatus(401); // No token
    }

    jwt.verify(token, SECRET_KEY, async(err, decoded) => {
        if (err) {
            console.log('Token verification failed:', err);
            return res.sendStatus(403); // Forbidden
        }

        try {
            const user = await User.findById(decoded.id).select('role');
            if (!user) {
                console.log('User not found in database');
                return res.sendStatus(404); // User not found
            }
            req.user = user; // Attach user info to the request
            console.log('Authenticated user:', req.user); // Log the authenticated user
            next();
        } catch (error) {
            console.error('Error fetching user from database:', error);
            return res.status(500).send('Internal server error');
        }
    });
};

// Middleware to check if the user is a librarian
const checkLibrarianRole = (req, res, next) => {
    if (!req.user) {
        console.log('User is undefined in checkLibrarianRole');
        return res.sendStatus(403); // Forbidden
    }

    console.log(`User role: ${req.user.role}`); // Log the user role

    if (req.user.role !== 'librarian') {
        return res.sendStatus(403); // Forbidden
    }
    next();
};
// API endpoint to get borrow history for a specific user
app.get('/api/userBorrows', authenticateToken, async (req, res) => {
    const { userid } = req.query;

    if (!userid || userid !== req.user.id) {
        return res.status(403).json({ error: 'You do not have permission to view this borrow history.' });
    }

    try {
        const borrows = await UserBorrow.find({ userid: userid });
        res.json(borrows);
    } catch (error) {
        console.error('Error fetching borrow history:', error);
        res.status(500).json({ error: 'Failed to fetch borrow history.' });
    }
});
// Function to set time to midnight
const setMidnight = (date) => {
    const midnightDate = new Date(date);
    midnightDate.setHours(0, 0, 0, 0); // Set hours, minutes, seconds, and milliseconds to 0
    return midnightDate;
};
// API endpoint to borrow a book by copyId

app.post('/api/books/copy_borrow', authenticateToken, async (req, res) => {
    const { userid, copyId, selectedCopies, isbn } = req.body;

    // Validate request body
    if (!userid || (!copyId && !selectedCopies)) {
        return res.status(400).json({ error: 'Missing required fields: userid and either copyId or selectedCopies.' });
    }

    // Ensure userid matches the authenticated user
    if (userid !== req.user.id) {
        return res.status(403).json({ error: 'You do not have permission to borrow these copies.' });
    }

    try {
        // Fetch the book by ISBN
        const book = await BookBuy.findOne({ industryIdentifier: isbn });

        if (!book) {
            return res.status(404).json({ error: 'Book not found.' });
        }

        // Determine which copies to borrow
        const copiesToBorrow = Array.isArray(selectedCopies) ? selectedCopies : [];
        if (copyId) {
            copiesToBorrow.push(copyId); // Add single copyId to the list
        }

        const borrowedCopies = [];
        const unavailableCopies = [];

        // Iterate through the requested copies and update their availability
        book.copies.forEach(copy => {
            if (copiesToBorrow.includes(copy.copyId)) {
                if (copy.availability) {
                    // Update the copy details for borrowing
                    copy.availability = false;
                    copy.borrowedDate = new Date();
                    copy.dueDate = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000); // 14 days from today
                    copy.status = 'borrowed'; // Set status to 'borrowed'
                    copy.borrowStatus = true; // Mark as borrowed
                    borrowedCopies.push(copy);
                } else {
                    unavailableCopies.push(copy.copyId);
                }
            }
        });

        // Handle unavailable copies
        if (unavailableCopies.length > 0) {
            return res.status(400).json({
                error: 'Some copies are unavailable.',
                unavailableCopies
            });
        }

        // Save the updated book document
        await book.save();

        // Synchronize the status in the EPC schema
        for (const copy of borrowedCopies) {
            if (copy.epc) {
                // Update the EPC status to 'borrowed'
                await EPC.updateOne(
                    { epc: copy.epc }, // Match the EPC number
                    { $set: { status: 'borrowed' } } // Set status to 'borrowed'
                );

                console.log(`Synchronized EPC "${copy.epc}" with status "borrowed".`);
            }
        }

        // Check if the user has an existing borrow record for this book
        let userBorrow = await UserBorrow.findOne({
            userid,
            industryIdentifier: { $in: [isbn] },
        });

        if (userBorrow) {
            // Update the existing record: append new copies to the copies array
            userBorrow.copies = [
                ...userBorrow.copies,
                ...borrowedCopies.map(copy => ({
                    copyId: copy.copyId,
                    bookLocation: copy.bookLocation || 'Unknown',
                    locationId: copy.locationId || 'Unknown',
                    borrowedDate: copy.borrowedDate,
                    dueDate: copy.dueDate,
                    epc: copy.epc, // Include the EPC number
                    status: 'borrowed', // Set status to 'borrowed'
                    availability: false, // Set availability to false
                    borrowStatus: true, // Set borrowStatus to true
                })),
            ];
        } else {
            // Create a new UserBorrow record
            userBorrow = new UserBorrow({
                userid,
                title: book.title,
                authors: book.authors || [],
                publisher: book.publisher || 'N/A',
                publishedDate: book.publishedDate || 'N/A',
                industryIdentifier: [isbn],
                copies: borrowedCopies.map(copy => ({
                    copyId: copy.copyId,
                    bookLocation: copy.bookLocation || 'Unknown',
                    locationId: copy.locationId || 'Unknown',
                    borrowedDate: copy.borrowedDate,
                    dueDate: copy.dueDate,
                    epc: copy.epc, // Include the EPC number
                    status: 'borrowed', // Set status to 'borrowed'
                    availability: false, // Set availability to false
                    borrowStatus: true, // Set borrowStatus to true
                })),
            });
        }

        // Save the updated UserBorrow record
        await userBorrow.save();

        // Log the borrowed copies with their EPC numbers
        console.log('Borrowed Copies with EPC Numbers:');
        borrowedCopies.forEach(copy => {
            console.log(`CopyId: ${copy.copyId}, EPC: ${copy.epc}`);
        });

        // Synchronize with BookBuy schema
        for (const copy of borrowedCopies) {
            await BookBuy.updateOne(
                { 'copies.copyId': copy.copyId }, // Match the copyId in the BookBuy schema
                { 
                    $set: { 
                        'copies.$.availability': false, 
                        'copies.$.status': 'borrowed', 
                     
                    } // Update the availability, status, and borrowStatus fields
                }
            );

            console.log(`Synchronized BookBuy copy "${copy.copyId}" as borrowed.`);
        }

        // Respond with redirect URL including valid copy IDs
        res.status(200).json({
            message: 'Copies borrowed successfully.',
            borrowedCopies: borrowedCopies.map(copy => ({
                copyId: copy.copyId,
                epc: copy.epc, // Include the EPC number in the response
                borrowedDate: copy.borrowedDate,
                dueDate: copy.dueDate,
                status: copy.status,
                borrowStatus: copy.borrowStatus,
            })),
            redirectUrl: `user_borrow_copy.html?userid=${userid}&isbn=${isbn}&copies=${copiesToBorrow.join(',')}`
        });
    } catch (error) {
        console.error('Error borrowing copies:', error);
        res.status(500).json({ error: error.message || 'Internal server error.' });
    }
});

app.post('/api/books/return', async (req, res) => {
    const { epc } = req.body;

    // Validate request body
    if (!epc) {
        return res.status(400).json({ error: 'EPC number is required.' });
    }

    try {
        // Find the EPC document and update its status to "in return box"
        const epcRecord = await EPC.findOneAndUpdate(
            { epc }, // Find by EPC number
            { $set: { status: 'in return box' } }, // Update the status to "in return box"
            { new: true } // Return the updated document
        );

        if (!epcRecord) {
            return res.status(404).json({ error: `EPC number '${epc}' not found.` });
        }

        console.log(`EPC status updated to "in return box" for EPC: ${epc}`);

        // Find the UserBorrow document that contains this EPC and update the corresponding copy
        const userBorrowRecord = await UserBorrow.findOneAndUpdate(
            { 'copies.epc': epc }, // Find the UserBorrow document with a copy that has this EPC
            { 
                $set: { 
                    'copies.$.status': 'in return box', 
                    'copies.$.availability': true, 
                    'copies.$.borrowStatus': false 
                } // Update the status, availability, and borrowStatus fields
            },
            { new: true } // Return the updated document
        );

        if (!userBorrowRecord) {
            return res.status(404).json({ error: `No UserBorrow record found for EPC '${epc}'.` });
        }

        console.log(`UserBorrow status updated to "in return box" for EPC: ${epc}`);

        // Find the BookBuy document and update the corresponding copy's availability
        const book = await BookBuy.findOneAndUpdate(
            { 'copies.epc': epc }, // Find the BookBuy document with a copy that has this EPC
            { 
                $set: { 
                    'copies.$.availability': true, 
                    'copies.$.status': 'in return box', 
                    'copies.$.borrowStatus': false 
                } // Update the availability, status, and borrowStatus fields
            },
            { new: true } // Return the updated document
        );

        if (!book) {
            return res.status(404).json({ error: `No BookBuy record found for EPC '${epc}'.` });
        }

        console.log(`BookBuy availability updated to "true" for EPC: ${epc}`);

        // Respond with success
        res.status(200).json({
            message: `Book with EPC '${epc}' returned successfully.`,
            epcRecord,
            userBorrowRecord,
            book,
        });
    } catch (error) {
        console.error('Error returning book:', error);
        res.status(500).json({ error: error.message || 'Internal server error.' });
    }
});


// Create default admin user if it doesn't exist
const createDefaultAdmin = async() => {
    const existingAdmin = await User.findOne({ username: 'admin' });
    if (!existingAdmin) {
        const hashedPassword = await bcrypt.hash('admin', 10);
        const adminUser = new User({ username: 'admin', password: hashedPassword, role: 'admin' });
        await adminUser.save();
        console.log('Default admin account created.');
    } else {
        console.log('Default admin account already exists.');
    }
};

// User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Find user by username
        const user = await User.findOne({ username });

        // Check if user exists and password is correct
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user._id, role: user.role }, // Payload
            SECRET_KEY, // Secret key
            { expiresIn: '1h' } // Token expiration
        );

        // Log successful login
        console.log(`User logged in: ${user.username}, Role: ${user.role}`);

        // Generate redirect URL based on role
        const redirectUrl =
            user.role === 'admin'
                ? '/admin.html'
                : user.role === 'librarian'
                ? `/index_logined.html?userid=${user._id}`
                : `/index_userlogined.html?userid=${user._id}`;

        // Return token and redirect URL
        console.log('Response:', { token, redirect: redirectUrl });
        return res.json({ token, redirect: redirectUrl });
       
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});
// User Signup
app.post('/users', async(req, res) => {
    const { username, password, role = 'user' } = req.body;
    console.log('Request body:', req.body);

    const existingUser = await User.findOne({ username });
    if (existingUser) {
        console.error('Signup failed: Username already exists.');
        return res.status(400).json({ error: 'Username already exists.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, role });
        await newUser.save();
        console.log(`User created: ${newUser.username}`);
        res.status(201).json(newUser);
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Failed to create user.' });
    }
});

// Passport configuration for Google

passport.use(new GoogleStrategy({
    clientID: '196205826526-a5i6cv0vp224tndtobsbep676cn537hm.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: 'https://comp-fyp.onrender.com/auth/google/callback',
    passReqToCallback: true
}, async (request, accessToken, refreshToken, profile, done) => {
    try {
        // Check if the user already exists
       
            console.log('Google profile:', profile);
    
            let user = await User.findOne({ googleId: profile.id });
            if (user) {
                console.log('Existing user:', user);
                return done(null, user);
            }
    
            user = new User({
                username: profile.displayName,
                googleId: profile.id,
                role: 'user'
            });
            await user.save();
            console.log('New user created:', user);
            return done(null, user);
        } catch (err) {
            console.error('Error in GoogleStrategy:', err);
            return done(err, null);
        }
    
}));
// Serialize User
passport.serializeUser((user, done) => {
    console.log('Serializing user:', user);
    done(null, user.id || user._id);
});

// Deserialize User
passport.deserializeUser(async (id, done) => {
    console.log('Deserializing user with ID:', id);
    try {
        const user = await User.findById(id);
        console.log('Deserialized user:', user);
        done(null, user);
    } catch (err) {
        console.error('Error in deserializeUser:', err);
        done(err, null);
    }
});


// Google auth routes
app.get('/auth/google', (req, res, next) => {
    console.log('Initiating Google authentication...');
    next();
}, passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        console.log('Google authentication successful. req.user:', req.user);

        if (!req.user) {
            console.error('Authentication successful, but req.user is undefined. Redirecting to /login.');
            return res.redirect('/login');
        }

        // Generate JWT token
        const token = jwt.sign({ id: req.user._id, role: req.user.role }, SECRET_KEY, { expiresIn: '1h' });
        console.log('Generated JWT token:', token);

        // Determine redirect URL
        const redirectUrl = req.user.role === 'admin' ? '/admin.html' :
            req.user.role === 'librarian' ? `https://comp-fyp.onrender.com/index_logined.html?userid=${req.user._id}&token=${token}` :
            `https://comp-fyp.onrender.com/index_userlogined.html?userid=${req.user._id}&token=${token}`;

        console.log(`Redirecting user with role "${req.user.role}" to: ${redirectUrl}`);
        res.redirect(redirectUrl);
    }
);

// API to get the username based on userid
app.get('/api/getUser', async (req, res) => {
    const { userid } = req.query;

    // Validate the input
    if (!userid) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    try {
        // Find the user in the User schema
        const user = await User.findById(userid).select('username');
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // Respond with the username
        res.status(200).json({ username: user.username });
    } catch (error) {
        console.error('Error fetching user:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// User Management (admin only)
app.get('/users', authenticateToken, async(req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    try {
        const users = await User.find();
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users.' });
    }
});


// Get user by ID
app.get('/api/users', async(req, res) => {
    try {
        // Extract userId from query parameters
        const userId = req.query.userid;

        // Extract token from headers
        const authHeader = req.headers['authorization']; // Get the Authorization header
        const token = authHeader && authHeader.split(' ')[1]
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        // Verify token
        const decoded = jwt.verify(token, 'YOUR_SECRET_KEY'); // Use your secret key
        if (!decoded) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        // Check if the user has an admin role
        const requestingUser = await User.findById(decoded.id).select('role'); // Assumes `id` is stored in the token
        if (!requestingUser || requestingUser.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: Admins only' });
        }

        // Fetch the requested user by userId from query parameters
        const user = await User.findById(userId).select('role');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(user); // Send user role back as JSON
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ message: 'Server error' });
    }
});


// User Update
app.put('/users/:id', authenticateToken, async(req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);

    try {
        const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!updatedUser) return res.status(404).json({ error: 'User not found.' });
        res.json(updatedUser);
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Failed to update user.' });
    }
});

// User Deletion
app.delete('/users/:id', authenticateToken, async(req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);

    try {
        await User.findByIdAndDelete(req.params.id);
        res.sendStatus(204);
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user.' });
    }
});


// API endpoint to search for books
app.get('/api/userbooks', authenticateToken, async(req, res) => {

    const search = req.query.q;

    try {
        const response = await axios.get(`https://www.googleapis.com/books/v1/volumes?q=${search}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A&maxResults=40`); // Replace with your actual API key

        const books = response.data.items;

        await Book.deleteMany({});

        for (const book of books) {
            // Check if the book has ISBN
            const industryIdentifiers = book.volumeInfo.industryIdentifiers || [];
            const hasISBN = industryIdentifiers.some(identifier =>
                identifier.type === 'ISBN_10' || identifier.type === 'ISBN_13'
            );

            // Only proceed if the book has an ISBN
            if (hasISBN) {
                const industryIdentifier = industryIdentifiers.find(identifier =>
                    identifier.type === 'ISBN_10' || identifier.type === 'ISBN_13'
                );

                // Use optional chaining correctly
                const identifierValue = industryIdentifier ? industryIdentifier.identifier : 'N/A';

                const newBook = new Book({
                    googleId: book.id,
                    industryIdentifier: identifierValue,
                    title: book.volumeInfo.title,
                    subtitle: book.volumeInfo.subtitle || 'N/A',
                    authors: book.volumeInfo.authors || [],
                    publisher: book.volumeInfo.publisher || 'N/A',
                    publishedDate: book.volumeInfo.publishedDate || 'N/A',
                    description: book.volumeInfo.description || 'N/A',
                    pageCount: book.volumeInfo.pageCount || 0,
                    categories: book.volumeInfo.categories || [],
                    language: book.volumeInfo.language || 'N/A',
                    coverImage: book.volumeInfo.imageLinks ? book.volumeInfo.imageLinks.thumbnail : '',
                    smallThumbnail: book.volumeInfo.imageLinks ? book.volumeInfo.imageLinks.smallThumbnail : '',
                    infoLink: book.volumeInfo.infoLink || '',
                    saleInfo: book.saleInfo || {},
                    accessInfo: book.accessInfo || {},
                    searchInfo: book.searchInfo || {},
                    previewLink: book.volumeInfo.previewLink || '',
                });

                await newBook.save();
            }
        }

        res.json({
            data: books.filter(book => {
                const industryIdentifiers = book.volumeInfo.industryIdentifiers || [];
                return industryIdentifiers.some(identifier =>
                    identifier.type === 'ISBN_10' || identifier.type === 'ISBN_13'
                );
            })
        });
    } catch (error) {
        console.error('Error fetching data from Google Books API:', error);
        res.status(500).json({ error: 'Error fetching data' });
    }
});
// API endpoint to search for books(librarian only)
app.get('/api/books', authenticateToken, async(req, res) => {
    if (req.user.role !== 'librarian') return res.sendStatus(403);
    const search = req.query.q;

    try {
        const response = await axios.get(`https://www.googleapis.com/books/v1/volumes?q=${search}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A&maxResults=40`); // Replace with your actual API key

        const books = response.data.items;

        await Book.deleteMany({});

        for (const book of books) {
            // Check if the book has ISBN
            const industryIdentifiers = book.volumeInfo.industryIdentifiers || [];
            const hasISBN = industryIdentifiers.some(identifier =>
                identifier.type === 'ISBN_10' || identifier.type === 'ISBN_13'
            );

            // Only proceed if the book has an ISBN
            if (hasISBN) {
                const industryIdentifier = industryIdentifiers.find(identifier =>
                    identifier.type === 'ISBN_10' || identifier.type === 'ISBN_13'
                );

                // Use optional chaining correctly
                const identifierValue = industryIdentifier ? industryIdentifier.identifier : 'N/A';

                const newBook = new Book({
                    googleId: book.id,
                    industryIdentifier: identifierValue,
                    title: book.volumeInfo.title,
                    subtitle: book.volumeInfo.subtitle || 'N/A',
                    authors: book.volumeInfo.authors || [],
                    publisher: book.volumeInfo.publisher || 'N/A',
                    publishedDate: book.volumeInfo.publishedDate || 'N/A',
                    description: book.volumeInfo.description || 'N/A',
                    pageCount: book.volumeInfo.pageCount || 0,
                    categories: book.volumeInfo.categories || [],
                    language: book.volumeInfo.language || 'N/A',
                    coverImage: book.volumeInfo.imageLinks ? book.volumeInfo.imageLinks.thumbnail : '',
                    smallThumbnail: book.volumeInfo.imageLinks ? book.volumeInfo.imageLinks.smallThumbnail : '',
                    infoLink: book.volumeInfo.infoLink || '',
                    saleInfo: book.saleInfo || {},
                    accessInfo: book.accessInfo || {},
                    searchInfo: book.searchInfo || {},
                    previewLink: book.volumeInfo.previewLink || '',
                });

                await newBook.save();
            }
        }

        res.json({
            data: books.filter(book => {
                const industryIdentifiers = book.volumeInfo.industryIdentifiers || [];
                return industryIdentifiers.some(identifier =>
                    identifier.type === 'ISBN_10' || identifier.type === 'ISBN_13'
                );
            })
        });
    } catch (error) {
        console.error('Error fetching data from Google Books API:', error);
        res.status(500).json({ error: 'Error fetching data' });
    }
});

// API endpoint to get book details by googleId
// API endpoint to get book details by googleId
app.get('/api/books/:googleId', async (req, res) => {
    const { googleId } = req.params;

      // Validate googleId to prevent invalid values like "copies"
      if (!googleId || googleId.toLowerCase() === "copies") {
        return res.status(400).json({ error: "Invalid googleId" });
    }

    console.log('Received googleId:', googleId);

    try {
        // First, check if the book exists in the local database
        const book = await Book.findOne({ googleId });
        
        if (book) {
            // If the book is found in the database, return it
            return res.json(book);
        }

        // If the book is not found in the database, fetch from Google Books API
        const googleBooksApiUrl = `https://www.googleapis.com/books/v1/volumes/${googleId}?key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A`;
        console.log('Fetching from URL:', googleBooksApiUrl);
        const response = await axios.get(googleBooksApiUrl);
        
        if (!response.data || !response.data.volumeInfo) {
            return res.status(404).json({ error: 'Book not found in Google Books API response' });
        }

        // Optionally, you can save the fetched book to your database here
        // const newBook = new Book(response.data.volumeInfo);
        // await newBook.save();

        // Return the book details from Google Books API
        res.json(response.data.volumeInfo);
    } catch (error) {
        console.error('Error fetching book details:', error.message);
        res.status(500).json({ error: 'Error fetching book details' });
    }
});


// API endpoint to get book details by ISBN
// API endpoint to get book details by ISBN
// API endpoint to get book details by ISBN
app.get('/api/books/isbn/:isbn', async (req, res) => {
    const { isbn } = req.params;

    try {
        // Check if the book already exists in the local database by ISBN
        let book = await Book.findOne({ industryIdentifier: isbn });

        if (!book) {
            // If the book is not found, fetch from Google Books API
            const googleBooksApiUrl = `https://www.googleapis.com/books/v1/volumes?q=isbn:${isbn}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A`;
            console.log('Fetching from Google Books API:', googleBooksApiUrl);

            const response = await axios.get(googleBooksApiUrl);
            const items = response.data.items;

            if (!items || items.length === 0) {
                return res.status(404).json({ error: 'Book not found by ISBN' });
            }

            const googleBook = items[0]; // Assuming the first result is the desired book

            // Check if the book with the same googleId already exists
            const existingBook = await Book.findOne({ googleId: googleBook.id });

            if (existingBook) {
                console.log(`Book with googleId ${googleBook.id} already exists. Returning the existing book.`);
                return res.json(existingBook); // Return the existing book
            }

            // Create a new book entry from Google Books API data
            const newBook = new Book({
                googleId: googleBook.id,
                industryIdentifier: isbn,
                title: googleBook.volumeInfo.title,
                subtitle: googleBook.volumeInfo.subtitle || 'N/A',
                authors: googleBook.volumeInfo.authors || [],
                publisher: googleBook.volumeInfo.publisher || 'N/A',
                publishedDate: googleBook.volumeInfo.publishedDate || 'N/A',
                description: googleBook.volumeInfo.description || 'N/A',
                pageCount: googleBook.volumeInfo.pageCount || 0,
                categories: googleBook.volumeInfo.categories || [],
                language: googleBook.volumeInfo.language || 'N/A',
                coverImage: googleBook.volumeInfo.imageLinks ? googleBook.volumeInfo.imageLinks.thumbnail : '',
                smallThumbnail: googleBook.volumeInfo.imageLinks ? googleBook.volumeInfo.imageLinks.smallThumbnail : '',
                infoLink: googleBook.volumeInfo.infoLink || '',
                saleInfo: googleBook.saleInfo || {},
                accessInfo: googleBook.accessInfo || {},
                searchInfo: googleBook.searchInfo || {},
                previewLink: googleBook.volumeInfo.previewLink || '',
            });

            // Save the new book to the database
            await newBook.save();
            book = newBook; // Update the reference to the newly saved book
        }

        res.json(book);
    } catch (error) {
        console.error('Error fetching book details by ISBN:', error);
        res.status(500).json({ error: 'Error fetching book details' });
    }
});
// Book Management (librarian only)
app.get('/books', authenticateToken, async(req, res) => {
    if (req.user.role !== 'librarian') return res.sendStatus(403);
    const search = req.query.search || '';
    try {
        const books = await Book.find({
            $or: [
                { title: new RegExp(search, 'i') },
                { authors: new RegExp(search, 'i') }
            ]
        });
        res.json(books);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/books', authenticateToken, async(req, res) => {
    if (req.user.role !== 'librarian') return res.sendStatus(403);
    const newBook = new Book(req.body);
    await newBook.save();
    res.json(newBook);
});

app.put('/books/:id', authenticateToken, async(req, res) => {
    if (req.user.role !== 'librarian') return res.sendStatus(403);
    await Book.findByIdAndUpdate(req.params.id, req.body);
    res.status(204).send();
});

app.delete('/books/:id', authenticateToken, async(req, res) => {
    if (req.user.role !== 'librarian') return res.sendStatus(403);
    await Book.findByIdAndDelete(req.params.id);
    res.status(204).send();
});
// API endpoint to create a comment
// API endpoint to create a comment
app.post('/api/comments', authenticateToken, async (req, res) => {
    const { bookId, rating, comment } = req.body;

    if (!bookId || !rating || !comment) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        // Create a new comment object
        const newComment = {
            rating,
            comment,
            date: new Date(), // Use the current date
        };

        // Update the `UserBorrow` document by adding the comment to the `comments` array
        const updatedUserBorrow = await UserBorrow.findByIdAndUpdate(
            bookId, // Match the `UserBorrow` document with the given `bookId`
            { $push: { comments: newComment } }, // Push the new comment into the `comments` array
            { new: true } // Return the updated document
        );

        if (!updatedUserBorrow) {
            return res.status(404).json({ error: 'Book not found in borrow records.' });
        }

        res.status(201).json({ message: 'Comment added successfully.', updatedUserBorrow });
    } catch (error) {
        console.error('Error adding comment:', error);
        res.status(500).json({ error: 'Failed to add comment.' });
    }
});
// API endpoint to update a comment
app.put('/api/comments/:id', authenticateToken, async(req, res) => {
    const { id } = req.params;
    const { rating, comment } = req.body;

    if (!rating || !comment) {
        return res.status(400).json({ error: 'Rating and comment are required.' });
    }

    try {
        const updatedComment = await Comment.findByIdAndUpdate(id, { rating, comment }, { new: true });

        if (!updatedComment) {
            return res.status(404).json({ error: 'Comment not found' });
        }

        res.json(updatedComment);
    } catch (error) {
        console.error('Error updating comment:', error);
        res.status(500).json({ error: 'Failed to update comment' });
    }
});

app.get('/api/comments', async (req, res) => {
    const { isbn } = req.query;

    if (!isbn) {
        return res.status(400).json({ error: 'ISBN is required.' });
    }

    try {
        const book = await UserBorrow.findOne({ 'industryIdentifier': isbn });

        if (!book) {
            return res.status(404).json({ error: 'Book not found.' });
        }

        res.status(200).json({ comments: book.comments });
    } catch (error) {
        console.error('Error fetching comments:', error);
        res.status(500).json({ error: 'Failed to fetch comments.' });
    }
});

const calculateAverageRating = (comments) => {
    if (!comments || comments.length === 0) return 0;
    const totalRating = comments.reduce((sum, comment) => sum + comment.rating, 0);
    return totalRating / comments.length;
};

app.get('/api/booksWithRatings', async (req, res) => {
    try {
        const books = await UserBorrow.find();

        const booksWithRatings = books.map(book => ({
            ...book.toObject(),
            averageRating: calculateAverageRating(book.comments), // Calculate average rating
        }));

        res.status(200).json({ data: booksWithRatings });
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).json({ error: 'Failed to fetch books with ratings.' });
    }
});

// API to get books purchased within the last month
app.get('/api/newArrivals', async (req, res) => {
    try {
        const oneMonthAgo = new Date();
        oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1); // Calculate the date one month ago

        // Query books purchased within the last month
        const newBooks = await BookBuy.find({
            purchaseDate: { $gte: oneMonthAgo },
        });

        res.status(200).json({ data: newBooks });
    } catch (error) {
        console.error('Error fetching new arrivals:', error);
        res.status(500).json({ error: 'Failed to fetch new arrivals.' });
    }
});
async function assignEPCsToExistingCopies(bookTitle, bookAuthors) {
    try {
        // Debug: Log the input parameters
        console.log('Book Title:', bookTitle);
        console.log('Book Authors:', bookAuthors);

        // Search for EPC records with matching title and authors
        const epcRecords = await EPC.find({
            title: { $regex: new RegExp(bookTitle, 'i') }, // Case-insensitive match
            author: { $all: bookAuthors }, // Match all authors exactly
        });

        console.log('EPC Records Found:', epcRecords);

        if (!epcRecords || epcRecords.length === 0) {
            console.log(`No EPC records found for book "${bookTitle}".`);
            return;
        }

        // Fetch the corresponding BookBuy record
        const bookBuy = await BookBuy.findOne({
            title: { $regex: new RegExp(bookTitle, 'i') }, // Match the title
            authors: { $all: bookAuthors }, // Match all authors
        });

        if (!bookBuy) {
            console.log(`No BookBuy record found for book "${bookTitle}".`);
            return;
        }

        console.log('BookBuy Found:', bookBuy);

        let epcIndex = 0; // Start assigning EPCs from the first record

        // Iterate through the copies in the BookBuy document
        for (let copy of bookBuy.copies) {
            // Assign EPC to copies that don't already have one
            if (!copy.epc && epcIndex < epcRecords.length) {
                const assignedEPC = epcRecords[epcIndex].epc; // Get the EPC number
                copy.epc = assignedEPC;
                copy.status = epcRecords[epcIndex].status; // Copy the status from the EPC record

                // Synchronize the EPC with the UserBorrow schema
                const result = await UserBorrow.updateOne(
                    { 'copies.copyId': copy.copyId }, // Match by copyId
                    { $set: { 'copies.$.epc': assignedEPC } } // Update the EPC in UserBorrow
                );

                console.log(`Synchronized EPC "${assignedEPC}" for copyId "${copy.copyId}" in UserBorrow:`, result);

                epcIndex++; // Move to the next EPC
            }
        }

        // Save the updated BookBuy document
        await bookBuy.save();

        console.log(`EPCs assigned to copies for book "${bookTitle}" and synchronized with UserBorrow.`);
    } catch (error) {
        console.error('Error assigning EPCs to existing copies:', error);
    }
}

// Route to get user role
app.get('/api/user-role', async(req, res) => {
    try {
        // Extract token from headers
        const authHeader = req.headers['authorization']; // Get the Authorization header
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        // Verify token
        const decoded = jwt.verify(token, SECRET_KEY); // Use your secret key
        if (!decoded) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        // Fetch the user role from the database using the user ID from the token
        const user = await User.findById(decoded.id).select('role');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Respond with the user's role
        res.json({ role: user.role });
    } catch (error) {
        console.error('Error fetching user role:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// API endpoint to get purchase history for a specific user
app.get('/api/userPurchases', authenticateToken, async (req, res) => {
    const { userid } = req.query;

    try {
        const purchases = await BookBuy.find({ userid: userid }).lean(); // Use lean() for better performance

        if (!purchases.length) {
            return res.status(404).json({ message: 'No purchases found.' });
        }

        // Ensure industryIdentifier is always an array
        const updatedPurchases = purchases.map(purchase => {
            if (!Array.isArray(purchase.industryIdentifier)) {
                purchase.industryIdentifier = [purchase.industryIdentifier].filter(Boolean); // Wrap non-array values
            }
            return purchase;
        });

        res.json(updatedPurchases);
    } catch (error) {
        console.error('Error fetching purchase history:', error);
        res.status(500).json({ error: 'Failed to fetch purchase history.' });
    }
});

// API endpoint to create a user purchase
function generateEPC(prefix, copyIndex) {
    const randomNumber = Math.floor(100 + Math.random() * 900); // Generate a random 3-digit number
    const suffix = String(copyIndex).padStart(3, '0'); // Pad the copy index with leading zeros to make it 3 digits
    return `${prefix}${randomNumber}${suffix}`;
}
app.post('/api/userPurchases', authenticateToken, async (req, res) => {
    const { industryIdentifier, userid, quantity } = req.body;

    // Validate request body
    if (!industryIdentifier || !userid || !quantity) {
        return res.status(400).json({ error: 'Missing industryIdentifier, userid, or quantity.' });
    }

    // Ensure userid matches the authenticated user
    if (userid !== req.user.id) {
        return res.status(403).json({ error: 'You do not have permission to make this purchase.' });
    }

    try {
        // Fetch book details based on the industryIdentifier (ISBN)
        const book = await Book.findOne({ industryIdentifier });
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        // Check if a purchase with the same industryIdentifier already exists
        let existingPurchase = await BookBuy.findOne({ industryIdentifier });

        const copies = [];
        const startingIndex = existingPurchase ? existingPurchase.copies.length + 1 : 1;

        // Define the EPC prefix (e.g., 010203)
        const epcPrefix = '010203';

        // Generate copies with unique `copyId`, `locationId`, and `epc`
        for (let i = 0; i < quantity; i++) {
            const copyIndex = startingIndex + i; // Calculate the current copy index
            const copyId = `${industryIdentifier}-${String(copyIndex).padStart(3, '0')}`;
            const locationId = generateLocationId(
                industryIdentifier,
                book.title,
                book.authors,
                book.publishedDate,
                book.categories[0] || 'Unknown',
                copyIndex
            );
            const epc = generateEPC(epcPrefix, copyIndex); // Generate the EPC with the prefix and copy index

            copies.push({
                copyId,
                bookLocation: 'Stanley Ho Library', // Default location
                locationId,
                availability: true,
                status: 'in library',
                epc,
            });
        }

        if (existingPurchase) {
            // Add new copies to the existing purchase record
            existingPurchase.copies.push(...copies);
            existingPurchase.quantity += quantity;
            await existingPurchase.save();

            return res.status(200).json({
                message: 'Purchase updated successfully',
                purchaseInfo: existingPurchase,
            });
        } else {
            // Create a new purchase record
            const newPurchase = new BookBuy({
                userid,
                industryIdentifier: Array.isArray(industryIdentifier) ? industryIdentifier : [industryIdentifier],
                title: book.title,
                subtitle: book.subtitle,
                authors: book.authors,
                publisher: book.publisher,
                publishedDate: book.publishedDate,
                description: book.description,
                pageCount: book.pageCount,
                categories: book.categories,
                language: book.language,
                coverImage: book.coverImage,
                purchaseDate: new Date(),
                quantity,
                copies,
            });

            const savedPurchase = await newPurchase.save();

            return res.status(201).json({
                message: 'Purchase recorded successfully',
                purchaseInfo: savedPurchase,
            });
        }
    } catch (error) {
        console.error('Error recording purchase:', error);
        res.status(500).json({ error: 'Error recording purchase' });
    }
});
// API endpoint to delete a user purchase
// API endpoint to delete a user purchase and its corresponding copy in admin books
app.delete('/api/userPurchases', authenticateToken, async (req, res) => {
    const { copyId, userid } = req.query;

    // Validate request parameters
    if (!copyId || !userid) {
        return res.status(400).json({ error: 'Missing copyId or userid.' });
    }

    // Ensure userid matches the authenticated user
    if (userid !== req.user.id) {
        console.log(`Permission denied. User ID: ${userid}, Authenticated User ID: ${req.user.id}`);
        return res.status(403).json({ error: 'You do not have permission to delete this purchase.' });
    }

    try {
        // Find the purchase record that contains the copyId
        const purchase = await BookBuy.findOne({ userid: userid, 'copies.copyId': copyId });

        if (!purchase) {
            return res.status(404).json({ error: 'Purchase or copy not found.' });
        }

        // Remove the specific copy from the `copies` array
        const updatedCopies = purchase.copies.filter(copy => copy.copyId !== copyId);

        // If no copies are left, delete the entire purchase record
        if (updatedCopies.length === 0) {
            await BookBuy.deleteOne({ _id: purchase._id });
        } else {
            // Otherwise, update the purchase record with the remaining copies
            purchase.copies = updatedCopies;
            purchase.quantity = updatedCopies.length; // Update the quantity
            await purchase.save();
        }

        res.json({ message: 'Copy deleted successfully.' });
    } catch (error) {
        console.error('Error deleting copy:', error);
        res.status(500).json({ error: 'Failed to delete the copy.' });
    }
});
// API endpoint to get all purchased books
app.get('/api/allUserPurchases', authenticateToken, async (req, res) => {
    try {
        const purchases = await BookBuy.find();

        if (!purchases.length) {
            return res.status(404).json({ message: 'No purchases found.' });
        }

        // Cache for Google Books API responses
        const googleBooksCache = new Map();

        const bookDetailsPromises = purchases.map(async (purchase) => {
            if (!purchase.googleId && (!purchase.industryIdentifier || purchase.industryIdentifier.length === 0)) {
                return { ...purchase.toObject(), googleBookDetails: null };
            }

            const cacheKey = purchase.googleId || purchase.industryIdentifier[0];
            if (googleBooksCache.has(cacheKey)) {
                return { ...purchase.toObject(), googleBookDetails: googleBooksCache.get(cacheKey) };
            }

            try {
                const response = purchase.googleId
                    ? await fetch(`https://www.googleapis.com/books/v1/volumes/${purchase.googleId}`)
                    : await fetch(`https://www.googleapis.com/books/v1/volumes?q=isbn:${purchase.industryIdentifier[0]}`);

                const data = await response.json();
                if (response.ok) {
                    googleBooksCache.set(cacheKey, data);
                    return { ...purchase.toObject(), googleBookDetails: data };
                }
            } catch (error) {
                console.error(`Error fetching Google Book details for ${cacheKey}:`, error);
            }

            return { ...purchase.toObject(), googleBookDetails: null };
        });

        const detailedPurchases = await Promise.all(bookDetailsPromises);
        res.status(200).json({ data: detailedPurchases });
    } catch (error) {
        console.error('Error fetching all user purchases:', error);
        res.status(500).json({ error: 'Error fetching user purchases' });
    }
});

// Update locationId for a specific book copy
function generateLocationId(isbn, title, authors, publishedDate, category, copyIndex = 1) {
    const lccCodes = {
        "Art": "N",
        "Biography & Autobiography": "CT",
        "Business & Economics": "HF",
        "Children's Books": "PZ",
        "Comics & Graphic Novels": "PN6728",
        "Computers": "QA76",
        "Cooking": "TX",
        "Crafts & Hobbies": "TT",
        "Drama": "PN",
        "Education": "L",
        "Fiction": "PS",
        "Foreign Language Study": "P",
        "Games": "GV",
        "Gardening": "SB",
        "Health & Fitness": "RA",
        "History": "D",
        "House & Home": "TX",
        "Humor": "PN",
        "Law": "K",
        "Literary Collections": "PN",
        "Literary Criticism": "PN",
        "Mathematics": "QA",
        "Medical": "R",
        "Music": "M",
        "Performing Arts": "NX",
        "Pets": "SF",
        "Philosophy": "B",
        "Photography": "TR",
        "Poetry": "PN",
        "Political Science": "J",
        "Psychology": "BF",
        "Reference": "Z",
        "Religion": "BL",
        "Science": "Q",
        "Self-Help": "BF",
        "Social Science": "H",
        "Sports & Recreation": "GV",
        "Study Aids": "LB",
        "Technology & Engineering": "T",
        "Transportation": "HE",
        "Travel": "G",
        "True Crime": "HV",
        "Young Adult Fiction": "PZ",
        "Young Adult Nonfiction": "PZ",
        "Fantasy": "PZ",
        "Science Fiction": "PZ",
        "Horror": "PZ",
        "Romance": "PS",
        "Mystery": "PS",
        "Thriller": "PS",
        "Adventure": "PZ",
        "Parenting": "HQ",
        "Philosophy & Religion": "B",
        "Unknown": "UNKNOWN"
    };

    const lccCode = lccCodes[category] || "UNKNOWN";
    const titleCode = title?.substring(0, 2).toUpperCase().padEnd(2, "X") || "XX";
    const authorCode = authors?.length > 0
        ? authors[0]?.substring(0, 2).toUpperCase().padEnd(2, "X")
        : "XX";

    // Extract the year from the publishedDate
    const year = publishedDate
        ? (publishedDate.match(/\d{4}/)?.[0] || "0000") // Use regex to extract the year
        : "0000";

    const suffix = copyIndex.toString().padStart(2, "0"); // Suffix for copy index

    const locationId = `${lccCode}.${titleCode}.${authorCode}.${year}.${suffix}`;
    console.log("Generated locationId:", locationId); // Debug log
    return locationId;
}
async function saveEPC(epcData) {
    try {
        console.log(`Checking if EPC exists: ${epcData.epc}`);
        const existingEPC = await EPC.findOne({ epc: epcData.epc });
        if (existingEPC) {
           
            return { duplicate: true, epc: epcData.epc };
        }

        // Create a new EPC record
        const newEPC = new EPC(epcData);
        await newEPC.save();
        console.log(`EPC saved successfully: ${epcData.epc}`);
        return { duplicate: false, epc: epcData.epc };
    } catch (error) {
        console.error(`Failed to save EPC: ${epcData.epc}`, error.message);
        throw new Error(`Failed to save EPC: ${epcData.epc}`);
    }
}

// Process books from parsed CSV data
async function processBooks(books, errors) {
    for (const book of books) {
        try {
            const requiredFields = ['title', 'authors', 'industryIdentifier', 'copyId', 'bookLocation', 'epc'];

            // Check for missing fields
            const missingFields = requiredFields.filter((field) => !book[field] || book[field].trim() === '');
            if (missingFields.length > 0) {
                errors.push({
                    error: 'Missing required fields.',
                    book,
                    missingFields
                });
                continue; // Skip this book
            }

            // Sanitize and validate fields
            const isAvailable = book.availability?.toLowerCase() === 'true';
            const sanitizedStatus = ['borrowed', 'in return box', 'in library'].includes(book.status?.toLowerCase())
                ? book.status.toLowerCase()
                : 'in library';

            // Handle existing book or create a new one
            const existingBook = await BookBuy.findOne({ industryIdentifier: book.industryIdentifier.trim() });
            if (existingBook) {
                // Add a new copy to the existing book
                const existingCopy = existingBook.copies.find((copy) => copy.copyId === book.copyId.trim());
                if (!existingCopy) {
                    existingBook.copies.push({
                        copyId: book.copyId.trim(),
                        bookLocation: book.bookLocation.trim(),
                        locationId: generateLocationId(book.industryIdentifier, book.title, book.authors),
                        availability: isAvailable,
                        status: sanitizedStatus,
                        epc: book.epc.trim()
                    });
                    existingBook.quantity = existingBook.copies.length;
                    await existingBook.save();
                }
            } else {
                // Create a new book with the given copy
                const newBook = new BookBuy({
                    title: book.title.trim(),
                    authors: book.authors.split(',').map((a) => a.trim()),
                    industryIdentifier: [book.industryIdentifier.trim()],
                    publisher: book.publisher?.trim() || '',
                    publishedDate: book.publishedDate?.trim() || '',
                    description: book.description?.trim() || '',
                    pageCount: parseInt(book.pageCount, 10) || 0,
                    categories: book.categories?.split(',').map((c) => c.trim()) || [],
                    language: book.language?.trim() || '',
                    coverImage: book.coverImage?.trim() || '',
                    quantity: 1,
                    copies: [
                        {
                            copyId: book.copyId.trim(),
                            bookLocation: book.bookLocation.trim(),
                            locationId: generateLocationId(book.industryIdentifier, book.title, book.authors),
                            availability: isAvailable,
                            status: sanitizedStatus,
                            epc: book.epc.trim()
                        }
                    ]
                });
                await newBook.save();
            }
        } catch (error) {
            errors.push({ error: 'Failed to process book.', book, details: error.message });
        }
    }
}

// API endpoint to export all purchases to CSV
const { Parser } = require('json2csv'); // Import the Parser from json2csv

app.get('/api/exportBooks', async (req, res) => {
    try {
        const purchases = await BookBuy.find();

        if (!purchases.length) {
            return res.status(404).json({ message: 'No purchases found.' });
        }

        const csvData = purchases.flatMap((purchase) =>
            purchase.copies.map((copy) => ({
                userId: purchase.userid,
                googleId: purchase.googleId,
                industryIdentifier: purchase.industryIdentifier.join(', '),
                title: purchase.title,
                authors: purchase.authors.join(', '),
                publisher: purchase.publisher,
                publishedDate: purchase.publishedDate,
                description: purchase.description,
                categories: purchase.categories.join(', '),
                language: purchase.language || 'N/A',
                coverImage: purchase.coverImage || 'N/A',
                purchaseDate: new Date(purchase.purchaseDate).toLocaleDateString(),
                bookLocation: copy.bookLocation || 'N/A',
                locationId: copy.locationId || 'N/A',
                availability: copy.availability,
                copyId: copy.copyId || 'N/A',
                epc: copy.epc || 'N/A',
                quantity: purchase.quantity || 0,
            }))
        );

        const json2csvParser = new Parser(); // Create a new instance of Parser
        const csv = json2csvParser.parse(csvData); // Convert JSON to CSV

        res.header('Content-Type', 'text/csv');
        res.attachment('purchases.csv');
        res.send(csv);
    } catch (error) {
        console.error('Error exporting books:', error);
        res.status(500).json({ error: 'Error exporting books' });
    }
});

// API endpoint to get all purchases
app.get('/api/allPurchases', async (req, res) => {
    try {
        const purchases = await BookBuy.find();

        if (!purchases.length) {
            console.log('No purchases found.'); // Log the message in the console
            return res.status(200).json([]); // Return an empty array with 200 OK status
        }

        res.status(200).json(purchases);
    } catch (error) {
        console.error('Error fetching all purchases:', error);
        res.status(500).json({ error: 'Error fetching all purchases' });
    }
});
// API endpoint to delete a purchase by ObjectId

// Delete a specific book copy
// Delete a specific book copy
// Delete a specific book copy by its unique ObjectId

app.delete('/api/deleteCopy/:id', async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ error: 'Invalid ObjectId format for id.' });
    }

    try {
        const book = await BookBuy.findOne({ 'copies._id': id });

        if (!book) {
            return res.status(404).json({ error: 'Book or copy not found.' });
        }

        book.copies = book.copies.filter((copy) => copy._id.toString() !== id);

        if (book.copies.length === 0) {
            await BookBuy.deleteOne({ _id: book._id });
        } else {
            await book.save();
        }

        res.status(200).json({ message: 'Book copy deleted successfully.' });
    } catch (error) {
        console.error('Error deleting book copy:', error);
        res.status(500).json({ error: 'Failed to delete book copy.' });
    }
});
// API endpoint to edit a book copy's quantity and EPC


app.put('/api/editBookCopy/:id', async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ error: 'Invalid ObjectId format for id.' });
    }

    try {
        const book = await BookBuy.findOne({ 'copies._id': id });

        if (!book) {
            return res.status(404).json({ error: 'Book or copy not found.' });
        }

        const copy = book.copies.id(id);
        if (!copy) {
            return res.status(404).json({ error: 'Copy not found.' });
        }

        const { copyId, bookLocation, availability, epc, quantity } = req.body;
        copy.copyId = copyId;
        copy.bookLocation = bookLocation;
        copy.availability = availability;
        copy.epc = epc;
        copy.quantity = quantity;

        await book.save();

        res.status(200).json({ message: 'Book copy updated successfully.' });
    } catch (error) {
        console.error('Error updating book copy:', error);
        res.status(500).json({ error: 'Failed to update book copy.' });
    }
});
// API endpoint to delete a book by its ObjectId
app.delete('/api/deleteBook/:id', async (req, res) => {
    const { id } = req.params;

    // Validate the ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ error: 'Invalid ObjectId format for id.' });
    }

    try {
        // Find and delete the book by its ObjectId
        const book = await BookBuy.findById(id);

        if (!book) {
            return res.status(404).json({ error: 'Book not found.' });
        }

        await BookBuy.deleteOne({ _id: id });

        res.status(200).json({ message: 'Book deleted successfully.' });
    } catch (error) {
        console.error('Error deleting book:', error);
        res.status(500).json({ error: 'Failed to delete book.' });
    }
});
// Helper function to fetch and update current loans
async function updateCurrentLoans(userId) {
    try {
        // Fetch borrow records where copies have status "borrowed"
        const userBorrows = await UserBorrow.find({ userid: userId, 'copies.status': 'borrowed' });

        console.log(`[DEBUG] Fetched UserBorrow records for userId ${userId}:`, userBorrows);

        // Map the borrow records to match the loanDetailsSchema
        const currentLoans = userBorrows.map(borrow => ({
            borrowId: borrow._id,
            details: {
                title: borrow.title,
                authors: borrow.authors,
                publisher: borrow.publisher,
                publishedDate: borrow.publishedDate,
                industryIdentifier: borrow.industryIdentifier,
                copies: borrow.copies.filter(copy => copy.status === 'borrowed'), // Only include borrowed copies
                comments: borrow.comments.map(comment => ({
                    rating: comment.rating,
                    comment: comment.comment,
                    date: comment.date,
                })),
                googleId: borrow.googleId,
                returned: borrow.copies.every(copy => copy.status !== 'borrowed'), // True if all copies are returned
            },
        }));

        console.log(`[DEBUG] Mapped currentLoans for userId ${userId}:`, currentLoans);

        return currentLoans;
    } catch (error) {
        console.error('[ERROR] Failed to update current loans:', error.message);
        throw new Error('Failed to fetch current loans.');
    }
}
const crypto = require('crypto');

// Function to generate a unique library card ID
function generateLibraryCardId() {
    return `LIB-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

// API endpoint to save or update user details
app.post('/api/userDetails', authenticateToken, async (req, res) => {
    const { userId, name, email, phone } = req.body;

    if (!userId || !name || !email || !phone) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        let userDetails = await UserDetails.findOne({ userId });

        if (userDetails) {
            // Check if library card exists; if not, generate one
            if (!userDetails.libraryCard) {
                userDetails.libraryCard = generateLibraryCardId();
            }

            // Update user details
            userDetails.name = name;
            userDetails.email = email;
            userDetails.phone = phone;

            await userDetails.save();
            return res.status(200).json({ message: 'User details updated successfully.', userDetails });
        } else {
            // Generate a new library card for the new user
            const libraryCard = generateLibraryCardId();

            // Create new user details
            userDetails = new UserDetails({
                userId,
                name,
                email,
                phone,
                libraryCard,
                currentLoans: [],
            });

            await userDetails.save();
            return res.status(201).json({ message: 'User details created successfully.', userDetails });
        }
    } catch (error) {
        console.error('[ERROR] Failed to save user details:', error.message);
        return res.status(500).json({ error: error.message });
    }
});

// API endpoint to fetch user details
app.get('/api/userDetails', authenticateToken, async (req, res) => {
    const { userid } = req.query;

    if (!userid) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    try {
        let userDetails = await UserDetails.findOne({ userId: userid });

        // If user details do not exist, create a new document
        if (!userDetails) {
            const libraryCard = generateLibraryCardId();

            userDetails = new UserDetails({
                userId: userid,
                name: '',
                email: '',
                phone: '',
                libraryCard,
                currentLoans: [],
            });

            await userDetails.save();
        }

        return res.status(200).json(userDetails);
    } catch (error) {
        console.error('[ERROR] Failed to fetch user details:', error.message);
        return res.status(500).json({ error: error.message });
    }
});
// API to fetch and populate current loans for a user
app.get('/api/userDetails/:userId/currentLoans', async (req, res) => {
    const { userId } = req.params;

    try {
        // Fetch borrow records where copies have status "borrowed"
        const userBorrows = await UserBorrow.find({ userid: userId, 'copies.status': 'borrowed' });

        console.log(`[DEBUG] Fetched UserBorrow records for userId ${userId}:`, userBorrows);

        // Map the borrow records to the loanDetailsSchema structure
        const currentLoans = userBorrows.map(borrow => ({
            borrowId: borrow._id,
            details: {
                title: borrow.title,
                authors: borrow.authors,
                publisher: borrow.publisher,
                publishedDate: borrow.publishedDate,
                industryIdentifier: borrow.industryIdentifier,
                copies: borrow.copies.filter(copy => copy.status === 'borrowed'), // Only include borrowed copies
                comments: borrow.comments,
                googleId: borrow.googleId,
                returned: borrow.copies.every(copy => copy.status !== 'borrowed'), // True if all copies are returned
            },
        }));

        console.log(`[DEBUG] Mapped currentLoans for userId ${userId}:`, currentLoans);

        // Update currentLoans in UserDetails
        const userDetails = await UserDetails.findOneAndUpdate(
            { userId },
            { $set: { currentLoans } },
            { new: true, upsert: true }
        );

        console.log(`[DEBUG] Updated UserDetails for userId ${userId}:`, userDetails);

        res.json(userDetails.currentLoans);
    } catch (error) {
        console.error('Error fetching and updating current loans:', error);
        res.status(500).json({ error: 'Failed to fetch and update current loans.' });
    }
});
// API to get room booking records for a specific user
// API to get room booking records for a specific user
app.get('/api/roomBookings', async (req, res) => {
    const { userid } = req.query;

    // Validate the input
    if (!userid) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    try {
        // Find the user in the UserDetails collection
        const user = await UserDetails.findOne({ userId: userid }).populate({
            path: 'roomBookings',
            select: 'bookingId roomName date timeslot userEmail username',
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // If the user has no room bookings, return an empty array
        if (!user.roomBookings || user.roomBookings.length === 0) {
            return res.status(200).json([]);
        }

        // Transform the room bookings to include only relevant information
        const userRoomBookings = user.roomBookings.map(booking => ({
            bookingId: booking.bookingId,
            roomName: booking.roomName,
            date: booking.date,
            timeslot: booking.timeslot,
            userEmail: booking.userEmail,
            username: booking.username,
        }));

        res.status(200).json(userRoomBookings);
    } catch (error) {
        console.error('Error fetching room bookings:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});
// API to get event booking records for a specific user
// API to fetch event bookings for a specific user
app.get('/api/eventBookings', async (req, res) => {
    const { userid } = req.query;

    // Validate the input
    if (!userid) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    try {
        // Find the user in the UserDetails collection
        const user = await UserDetails.findOne({ userId: userid }).populate({
            path: 'eventBookings',
            select: 'eventId title venue time eventLink registeredUsers',
        });

        if (!user) {
            console.log(`[INFO] User not found for userId: ${userid}`);
            return res.status(404).json({ error: 'User not found.' });
        }

        // If the user has no event bookings, return an empty array
        if (!user.eventBookings || user.eventBookings.length === 0) {
            console.log(`[INFO] No event bookings found for userId: ${userid}`);
            return res.status(200).json([]);
        }

        // Transform the event bookings to include relevant user-specific information
        const userEventBookings = user.eventBookings.map(event => {
            const registeredUsers = Object.fromEntries(event.registeredUsers); // Convert Map to an object

            return {
                eventId: event.eventId,
                title: event.title,
                venue: event.venue,
                time: event.time,
                eventLink: event.eventLink,
                isUserRegistered: registeredUsers.hasOwnProperty(user.email), // Check if the user is registered
                registeredUsers, // Include all registered users
            };
        });

        // Respond with the user's event bookings
        res.status(200).json(userEventBookings);
    } catch (error) {
        console.error('[ERROR] Error fetching event bookings:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Route to redirect to the Privacy Policy URL
app.get('/privacy-policy', (req, res) => {
    res.redirect('https://www.privacypolicies.com/live/6aa4161f-bbe8-407c-aefe-24659a864dc3');
});

// Route to redirect to the Terms and Conditions URL
app.get('/terms-and-conditions', (req, res) => {
    res.redirect('https://www.privacypolicies.com/live/1108d4cd-d6e3-4ea0-b9b9-6cfb7aa2df1a');
});

// Utility function to format date to UTC
function formatDateToUTC(date) {
    return new Date(date).toUTCString(); // Converts date to a UTC string
}

// New route: POST /send-sendgrid-email
app.post('/send-sendgrid-email', async (req, res) => {
    try {
        // Fetch user details from the database (you can modify the query as needed)
        const userDetails = await UserDetails.findOne(); // Fetch the first user for demonstration

        if (!userDetails) {
            return res.status(404).send('No user found.');
        }

        const fromAddress = 'abbichiu@gmail.com'; // Sender email
        const toAddress = userDetails.email; // Recipient email from the user details

        if (!toAddress) {
            return res.status(400).send('Recipient address is required.');
        }

        // Compose the email including the current loans
        let loanDetailsText = 'Current Loans:\n\n';
        userDetails.currentLoans.forEach((loan, index) => {
            loanDetailsText += `Loan ${index + 1}:\n`;
            loanDetailsText += `Title: ${loan.details.title}\n`;
            loanDetailsText += `Authors: ${loan.details.authors.join(', ')}\n`;
            loanDetailsText += `Borrow Date: ${formatDateToUTC(loan.details.borrowDate)}\n`; // Convert to UTC
            loanDetailsText += `Due Date: ${formatDateToUTC(loan.details.dueDate)}\n`; // Convert to UTC
            loanDetailsText += `Returned: ${loan.details.returned ? 'Yes' : 'No'}\n`;
            loanDetailsText += `Comments: ${loan.details.comments.join(', ')}\n\n`;
        });

        const emailContent = `
Hello ${userDetails.name},

Here are your current loan details:

${loanDetailsText}

Best regards,
Library Team`;

        // Create the email object for SendGrid
        const msg = {
            to: toAddress, // Recipient email
            from: fromAddress, // Sender email
            subject: 'Your Current Loan Details',
            text: emailContent, // Plain text body
            html: `<pre>${emailContent}</pre>`, // HTML body (optional for better formatting)
        };

        // Send the email using SendGrid
        const response = await sgMail.send(msg);

        // Log success message and return response
        console.log(`Email sent successfully to ${toAddress}. Response:`, response);
        res.status(200).send(`Email sent successfully! Response: ${JSON.stringify(response)}`);
    } catch (error) {
        // Log error details
        console.error('Error sending email:', error.response ? error.response.body : error.message);
        res.status(500).send('Error sending email');
    }
});

// Fetch copies for a specific ISBN
app.get('/api/books/isbn/:isbn/copies', async (req, res) => {
    const { isbn } = req.params;

    if (!isbn) {
        console.log('ERROR: ISBN is missing in the request.');
        return res.status(400).json({ error: 'ISBN is required.' });
    }

    try {
        console.log(`INFO: Searching for book with ISBN: ${isbn}`);

        // Query the database for the book with the given ISBN
        const book = await BookBuy.findOne({ industryIdentifier: isbn });

        if (!book) {
            console.log(`ERROR: No book found for ISBN: ${isbn}`);
            return res.status(404).json({ error: 'Book not found.' });
        }

        console.log(`INFO: Found book: ${book.title}`);

        if (!book.copies || book.copies.length === 0) {
            console.log(`INFO: No copies available for book with ISBN: ${isbn}`);
            return res.status(200).json({ copies: [] });
        }

        console.log(`INFO: Copies found: ${JSON.stringify(book.copies, null, 2)}`);
        res.status(200).json({ copies: book.copies });
    } catch (error) {
        console.error('ERROR: An error occurred while fetching copies:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

const detectedEpcs = { shelf: new Map(), returnBox: new Map() };
const connectionStatus = new Map();

async function processShelfDetection(epc, readerIp) {
  try {
    const existingEpc = await Epc.findOne({ epc });
    const shelf = await Shelf.findOne({ readerIp });
    if (!shelf) throw new Error(`Shelf with IP ${readerIp} not found`);
    const logMessage = `${new Date().toLocaleTimeString()} - EPC '${epc}' detected by shelf reader ${readerIp}`;
    if (existingEpc) {
      if (existingEpc.status !== 'in library') {
        existingEpc.status = 'in library';
        existingEpc.readerIp = readerIp;
        existingEpc.timestamp = Date.now();
        existingEpc.logs = existingEpc.logs || [];
        existingEpc.logs.push({ message: logMessage, timestamp: Date.now() });
        await existingEpc.save();
        console.log(`EPC '${epc}' status changed to 'in library'`);
      } else {
        existingEpc.readerIp = readerIp;
        existingEpc.logs = existingEpc.logs || [];
        existingEpc.logs.push({ message: logMessage, timestamp: Date.now() });
        await existingEpc.save();
      }
    } else {
      const newEpc = new Epc({
        epc, title: 'Unknown Title', author: ['Unknown Author'], status: 'in library',
        readerIp, timestamp: Date.now(), logs: [{ message: logMessage, timestamp: Date.now() }]
      });
      await newEpc.save();
      console.log(`New EPC '${epc}' added to shelf`);
    }
  } catch (error) {
    console.error(`Error processing shelf EPC '${epc}':`, error.message);
    throw error;
  }
}

async function processReturn(epc, readerIp) {
  try {
    const existingEpc = await Epc.findOne({ epc });
    const returnBox = await ReturnBox.findOne({ readerIp });
    if (!returnBox) throw new Error(`Return box with IP ${readerIp} not found`);
    const logMessage = `${new Date().toLocaleTimeString()} - EPC '${epc}' detected by return box reader ${readerIp}`;
    if (existingEpc) {
      if (existingEpc.status !== 'in return box') {
        existingEpc.status = 'in return box';
        existingEpc.readerIp = readerIp;
        existingEpc.timestamp = Date.now();
        existingEpc.logs = existingEpc.logs || [];
        existingEpc.logs.push({ message: logMessage, timestamp: Date.now() });
        await existingEpc.save();
        console.log(`EPC '${epc}' status changed to 'in return box'`);
      } else {
        existingEpc.readerIp = readerIp;
        existingEpc.logs = existingEpc.logs || [];
        existingEpc.logs.push({ message: logMessage, timestamp: Date.now() });
        await existingEpc.save();
      }
    } else {
      const newEpc = new Epc({
        epc, title: 'Unknown Title', author: ['Unknown Author'], status: 'in return box',
        readerIp, timestamp: Date.now(), logs: [{ message: logMessage, timestamp: Date.now() }]
      });
      await newEpc.save();
      console.log(`New EPC '${epc}' added to return box`);
    }
  } catch (error) {
    console.error(`Error processing return box EPC '${epc}':`, error.message);
    throw error;
  }
}

app.post('/api/rfid-update',  async (req, res) => {
  const { readerIp, epc, type, detected = true } = req.body;
  if (!readerIp || !epc || !type) return res.status(400).json({ error: 'Missing fields' });
  const store = type === 'shelf' ? detectedEpcs.shelf : detectedEpcs.returnBox;
  try {
    if (detected) {
      console.log(`EPC '${epc}' detected by ${type} reader ${readerIp}`);
      if (type === 'shelf') await processShelfDetection(epc, readerIp);
      else if (type === 'return_box') await processReturn(epc, readerIp);
      store.set(epc, { timestamp: Date.now(), readerIp });
    } else {
      console.log(`EPC '${epc}' no longer detected by ${type} reader ${readerIp}`);
      store.delete(epc);
      const existingEpc = await Epc.findOne({ epc });
      if (existingEpc && existingEpc.status !== 'borrowed') {
        const logMessage = `${new Date().toLocaleTimeString()} - EPC '${epc}' no longer detected by ${type} reader ${readerIp}`;
        existingEpc.status = 'borrowed';
        existingEpc.readerIp = null;
        existingEpc.timestamp = Date.now();
        existingEpc.logs = existingEpc.logs || [];
        existingEpc.logs.push({ message: logMessage, timestamp: Date.now() });
        await existingEpc.save();
        console.log(`EPC '${epc}' status changed to 'borrowed'`);
      }
    }
    res.status(200).json({ message: 'EPC processed' });
  } catch (error) {
    console.error('Error processing EPC:', error.message);
    res.status(500).json({ error: error.message || 'Internal server error' });
  }
});

app.post('/api/connection-status', (req, res) => {
  const { readerIp, connected } = req.body;
  if (!readerIp || typeof connected !== 'boolean') return res.status(400).json({ error: 'Missing fields' });
  connectionStatus.set(readerIp, connected);
  res.status(200).json({ message: 'Connection status updated' });
});

app.get('/api/rfid-readers',  async (req, res) => {
  try {
    const allEpcs = await Epc.find().lean();
    const shelves = await Shelf.find().lean();
    const returnBoxes = await ReturnBox.find().lean();

    const shelfEpcs = Array.from(detectedEpcs.shelf.entries()).map(([epc, { timestamp, readerIp }]) => {
      const dbEpc = allEpcs.find(e => e.epc === epc) || {};
      const shelf = shelves.find(s => s.readerIp === readerIp) || { name: 'Unknown' };
      return { epc, timestamp, readerIp, shelfName: shelf.name, logs: dbEpc.logs || [], ...dbEpc };
    });

    const returnBoxEpcs = Array.from(detectedEpcs.returnBox.entries()).map(([epc, { timestamp, readerIp }]) => {
      const dbEpc = allEpcs.find(e => e.epc === epc) || {};
      const returnBox = returnBoxes.find(r => r.readerIp === readerIp) || { name: 'Unknown' };
      return { epc, timestamp, readerIp, returnBoxName: returnBox.name, logs: dbEpc.logs || [], ...dbEpc };
    });

    const shelfReaders = shelves.map(shelf => {
      const epcsForShelf = shelfEpcs.filter(epc => epc.readerIp === shelf.readerIp);
      return {
        readerIp: shelf.readerIp,
        name: shelf.name,
        status: connectionStatus.get(shelf.readerIp) ? 'active' : 'inactive',
        epcs: epcsForShelf,
      };
    });

    const returnBoxReaders = returnBoxes.map(box => {
      const epcsForBox = returnBoxEpcs.filter(epc => epc.readerIp === box.readerIp);
      return {
        readerIp: box.readerIp,
        name: box.name,
        status: connectionStatus.get(box.readerIp) ? 'active' : 'inactive',
        epcs: epcsForBox,
      };
    });

    res.json({
      shelves: shelfReaders,
      returnBoxes: returnBoxReaders,
    });
  } catch (error) {
    console.error('Error fetching readers:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/shelves',  async (req, res) => {
  const { name, readerIp } = req.body;
  if (!name || !readerIp) return res.status(400).json({ error: 'Name and readerIp required' });
  try {
    const existing = await Shelf.findOne({ readerIp });
    if (existing) return res.status(400).json({ error: 'Shelf exists' });
    const shelf = new Shelf({ name, readerIp });
    await shelf.save();
    res.status(201).json(shelf);
  } catch (error) {
    console.error('Error adding shelf:', error.message);
    res.status(500).json({ error: 'Failed to add shelf' });
  }
});

app.delete('/api/shelves/:readerIp',  async (req, res) => {
  const { readerIp } = req.params;
  try {
    await Shelf.deleteOne({ readerIp });
    connectionStatus.set(readerIp, false);
    res.status(200).json({ message: 'Shelf deleted' });
  } catch (error) {
    console.error('Error deleting shelf:', error.message);
    res.status(500).json({ error: 'Failed to delete shelf' });
  }
});

app.post('/api/return-boxes',  async (req, res) => {
  const { name, readerIp } = req.body;
  if (!name || !readerIp) return res.status(400).json({ error: 'Name and readerIp required' });
  try {
    const existing = await ReturnBox.findOne({ readerIp });
    if (existing) return res.status(400).json({ error: 'Return box exists' });
    const box = new ReturnBox({ name, readerIp });
    await box.save();
    res.status(201).json(box);
  } catch (error) {
    console.error('Error adding return box:', error.message);
    res.status(500).json({ error: 'Failed to add return box' });
  }
});

app.delete('/api/return-boxes/:readerIp',  async (req, res) => {
  const { readerIp } = req.params;
  try {
    await ReturnBox.deleteOne({ readerIp });
    connectionStatus.set(readerIp, false);
    res.status(200).json({ message: 'Return box deleted' });
  } catch (error) {
    console.error('Error deleting return box:', error.message);
    res.status(500).json({ error: 'Failed to delete return box' });
  }
});

app.post('/api/epc',  async (req, res) => {
  const { epc, title, author, status, industryIdentifier } = req.body;
  if (!epc || !title || !author || !status) return res.status(400).json({ error: 'EPC, title, author, status required' });
  if (!['borrowed', 'in return box', 'in library'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const existing = await Epc.findOne({ epc });
    if (existing) return res.status(400).json({ error: 'EPC exists' });
    const newEpc = new Epc({
      epc, title, author, status, industryIdentifier: industryIdentifier || ['N/A'],
      timestamp: Date.now(), logs: [{ message: `${new Date().toLocaleTimeString()} - EPC '${epc}' manually added`, timestamp: Date.now() }]
    });
    await newEpc.save();
    console.log(`Added EPC '${epc}' with status '${status}'`);
    res.status(201).json(newEpc);
  } catch (error) {
    console.error('Error adding EPC:', error.message);
    res.status(500).json({ error: 'Failed to add EPC' });
  }
});



// Start server and create default admin
app.listen(PORT, async() => {
    console.log(`Server running on http://:${PORT}`);
    await createDefaultAdmin();
});


// Catch-all route to redirect to index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});