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
const EPC = require('./models/epcSchema');
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
        const { eventName, userName, userEmail } = req.body;

        // Validate inputs
        if (!eventName || !userName || !userEmail) {
            console.log('Missing booking details');
            return res.status(400).json({ error: 'Missing booking details.' });
        }

        console.log(`Searching for event: ${eventName}`);

        // Find the event in the database
        const event = await Event.findOne({ title: eventName });

        if (!event) {
            console.log('Event not found in the database');
            return res.status(404).json({ error: 'Event not found.' });
        }

        console.log(`Event found: ${event.title}`);

        // Ensure `registeredUsers` is a Map
        if (!event.registeredUsers || !(event.registeredUsers instanceof Map)) {
            event.registeredUsers = new Map();
        }

        // Sanitize the email address for use as a key in the Map
        const sanitizedEmail = userEmail.replace(/\./g, '[dot]');

        // Check if the user is already registered
        if (event.registeredUsers.has(sanitizedEmail)) {
            console.log(`User ${userName} is already registered for event ${event.title}`);
            return res.status(400).json({ error: 'User already registered for this event.' });
        }

        // Add the sanitized email and user name to the `registeredUsers` map
        event.registeredUsers.set(sanitizedEmail, userName);

        // Save the updated event
        await event.save();

        console.log(`User ${userName} successfully registered for event ${event.title}`);

        // Update the `eventBookings` in the `UserDetails` schema
        const userDetails = await UserDetails.findOne({ email: userEmail });

        if (userDetails) {
            // Add the event to the user's `eventBookings` if not already present
            if (!userDetails.eventBookings.includes(event._id)) {
                userDetails.eventBookings.push(event._id);
                await userDetails.save();

                console.log(`Event ${eventName} added to user ${userName}'s bookings.`);
            }
        } else {
            console.log(`UserDetails not found for email: ${userEmail}`);
            return res.status(404).json({ error: 'User details not found. Please register the user first.' });
        }

        // Send confirmation email
        await sendBookingConfirmationEmail({ eventName, userName, userEmail });

        // Respond to the client
        res.status(200).json({
            message: `Booking confirmed for "${eventName}". A confirmation email has been sent to: ${userEmail}`,
        });
    } catch (error) {
        console.error('Error in /api/bookEvent:', error.message);

        // Handle specific errors for better feedback
        if (error.name === 'ValidationError') {
            return res.status(400).json({ error: 'Invalid input data.' });
        }

        res.status(500).json({ error: 'Internal server error.' });
    }
});

// API to fetch all registered users for each event
app.get('/api/events', async (req, res) => {
    try {
        // Fetch all events from the database
        const events = await Event.find({});

        // Map the event data to include registered users
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
                registeredUsers, // Object with emails as keys and user names as values
                eventLink: event.eventLink,
            };
        });

        // Send the formatted event data as a JSON response
        res.status(200).json(eventData);
    } catch (error) {
        console.error('Error fetching events:', error.message);
        res.status(500).json({ error: 'Internal server error while fetching events.' });
    }
});

// Configure multer for file upload
const upload = multer({ dest: 'uploads/' }); // Temporary storage for uploaded files
const { v4: uuidv4 } = require('uuid');

app.post('/api/uploadCsv', upload.single('csv'), async (req, res) => {
    try {
        const filePath = req.file.path; // Path to the uploaded file
        const rows = []; // Array to collect rows for processing later

        // Parse the CSV file
        fs.createReadStream(filePath)
            .pipe(csv({ headers: ['title', 'venue', 'time', 'eventLink'], skipEmptyLines: true }))
            .on('data', (row) => {
                rows.push(row); // Collect rows for processing later
            })
            .on('end', async () => {
                try {
                    for (const row of rows) {
                        // Sanitize and validate fields
                        const title = row.title?.trim();
                        const venue = row.venue?.trim();
                        const timeRaw = row.time?.trim();
                        const time = new Date(timeRaw); // Convert sanitized time to a Date object
                        const eventLink = row.eventLink?.trim();

                        // Validate required fields
                        if (!title || !venue || isNaN(time.getTime()) || !eventLink) {
                            console.error(`Invalid row data: ${JSON.stringify(row)}`);
                            continue; // Skip invalid rows
                        }

                        // Check if the event already exists by title
                        const existingEvent = await Event.findOne({ title });

                        if (existingEvent) {
                            // Update the existing event with new fields (excluding the title)
                            existingEvent.venue = venue;
                            existingEvent.time = time;
                            existingEvent.eventLink = eventLink;
                            await existingEvent.save();
                            console.log(`Updated event: ${title}`);
                        } else {
                            // Create a new event if it doesn't already exist
                            const newEvent = new Event({
                                eventId: uuidv4(), // Generate a unique eventId
                                title,
                                venue,
                                time,
                                eventLink,
                                registeredUsers: {}, // Initialize an empty map for registered users
                            });
                            await newEvent.save();
                            console.log(`Created new event: ${title}`);
                        }
                    }

                    res.status(200).json({ message: 'CSV processed successfully. Duplicate events were updated.' });
                } catch (error) {
                    console.error('Error processing rows:', error.message);
                    res.status(500).json({ error: 'Failed to process events.' });
                } finally {
                    // Clean up temporary files
                    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
                }
            })
            .on('error', (error) => {
                console.error('Error reading the CSV file:', error.message);
                res.status(500).json({ error: 'Error processing the CSV file.' });
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath); // Clean up temporary file on error
            });
    } catch (error) {
        console.error('Error in /api/uploadCsv:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});



app.put('/api/events/:eventId', async (req, res) => {
    try {
        const { eventId } = req.params;
        const { time } = req.body;

        const updatedFields = {};
        if (time !== undefined) updatedFields.time = time ? new Date(time) : null;

        const event = await Event.findOneAndUpdate({ eventId }, updatedFields, { new: true });

        if (!event) {
            return res.status(404).json({ error: 'Event not found.' });
        }

        res.status(200).json({ message: 'Event updated successfully.', event });
    } catch (error) {
        console.error('Error updating event:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.delete('/api/events/:eventId', async (req, res) => {
    try {
        const { eventId } = req.params;

        const event = await Event.findOneAndDelete({ eventId });

        if (!event) {
            return res.status(404).json({ error: 'Event not found.' });
        }

        res.status(200).json({ message: 'Event deleted successfully.' });
    } catch (error) {
        console.error('Error deleting event:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.delete('/api/deleteExpiredEvents', async (req, res) => {
    try {
        const now = new Date();
        const result = await Event.deleteMany({ time: { $lt: now } }); // Delete events with a time earlier than the current date
        res.status(200).json({ message: `Deleted ${result.deletedCount} expired events.` });
    } catch (error) {
        console.error('Error deleting expired events:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
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

        console.log(`Email sent successfully to ${toAddress}.`);
        return response;
    } catch (error) {
        console.error(`Error sending email to ${userDetails.email || 'Unknown Email'}:`, error.message);
        throw error;
    }
}

// Helper function to format dates to UTC
function formatDateToUTC(date) {
    const utcDate = new Date(date);
    return utcDate.toUTCString(); // Format date in UTC
}
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
                    await sendEmail(user, upcomingLoans);
                } catch (error) {
                    console.error(`Failed to send email to ${user.email}. Error:`, error.message);
                }
            }
        }

        res.status(200).json({ message: 'Reminder emails sent successfully!' });
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
app.get('/api/books/isbn/:isbn', async(req, res) => {
    const { isbn } = req.params;

    try {
        let book = await Book.findOne({ industryIdentifier: isbn });

        if (!book) {
            // Fetch from Google Books API if not found in database
            const response = await axios.get(`https://www.googleapis.com/books/v1/volumes?q=isbn:${isbn}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A`);
            const items = response.data.items;

            if (!items || items.length === 0) {
                return res.status(404).json({ error: 'Book not found by ISBN' });
            }

            const googleBook = items[0]; // Assuming the first result is the desired book

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

            await newBook.save();
            book = newBook; // Update book reference to the newly saved book
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

// API to get books purchased in the last 3 days
app.get('/api/newArrivals', async (req, res) => {
    try {
        const threeDaysAgo = new Date();
        threeDaysAgo.setDate(threeDaysAgo.getDate() - 3); // Calculate the date 3 days ago

        // Query books purchased within the last 3 days
        const newBooks = await BookBuy.find({
            purchaseDate: { $gte: threeDaysAgo },
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
app.get('/api/userPurchases', authenticateToken, async(req, res) => {
    const { userid } = req.query;


    try {
        const purchases = await BookBuy.find({ userid: userid });
        res.json(purchases);
    } catch (error) {
        console.error('Error fetching purchase history:', error);
        res.status(500).json({ error: 'Failed to fetch purchase history.' });
    }
});

// API endpoint to create a user purchase
app.post('/api/userPurchases', authenticateToken, async(req, res) => {
    console.log('Request Body:', req.body);
    const { googleId, userid } = req.body;

    // Validate request body
    if (!googleId || !userid) {
        return res.status(400).json({ error: 'Missing googleId or userid.' });
    }

    // Ensure userid matches the authenticated user
    if (userid !== req.user.id) {
        console.log(`Permission denied. User ID: ${userid}, Authenticated User ID: ${req.user.id}`);
        return res.status(403).json({ error: 'You do not have permission to make this purchase.' });
    }

    try {
        // Fetch book details based on googleId
        const book = await Book.findOne({ googleId });
        console.log('Fetched Book:', book);
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        // Check if a purchase with the same industryIdentifier already exists
        const existingPurchase = await BookBuy.findOne({ industryIdentifier: book.industryIdentifier });
        if (existingPurchase) {
            console.log(`Purchase already exists for ISBN: ${book.industryIdentifier}`);
            return res.status(409).json({ error: 'Purchase already exists for this ISBN.' });
        }

        // Create a new purchase record using the book details
        const purchase = new BookBuy({
            userid: userid,
            googleId: book.googleId,
            industryIdentifier: Array.isArray(book.industryIdentifier) ? book.industryIdentifier : [book.industryIdentifier],
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
            purchaseDate: new Date() // Automatically set the purchase date
        });

        const savedPurchase = await purchase.save();
        return res.status(201).json({
            message: 'Purchase recorded successfully',
            purchaseInfo: savedPurchase
        });
    } catch (error) {
        console.error('Error recording purchase:', error);
        return res.status(500).json({ error: 'Error recording purchase' });
    }
});
// API endpoint to delete a user purchase
// API endpoint to delete a user purchase and its corresponding copy in admin books
app.delete('/api/userPurchases', authenticateToken, async(req, res) => {
    const { copyId, userid } = req.query; // Change googleId to copyId

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
        // Delete the purchase record
        const purchaseResult = await BookBuy.deleteOne({ copyId: copyId, userid: userid });

        if (purchaseResult.deletedCount === 0) {
            return res.status(404).json({ error: 'Purchase not found.' });
        }

        // Delete the corresponding copy from the admin book collection
        const adminBookResult = await Book.deleteOne({ copyId: copyId });

        if (adminBookResult.deletedCount === 0) {
            return res.status(404).json({ error: 'Copy not found in admin books.' });
        }

        res.json({ message: 'Purchase and corresponding copy deleted successfully.' });
    } catch (error) {
        console.error('Error deleting purchase:', error);
        res.status(500).json({ error: 'Failed to delete purchase.' });
    }
});

// API endpoint to get all purchased books
app.get('/api/allUserPurchases', authenticateToken, async(req, res) => {
    try {
        // Find all purchases
        const purchases = await BookBuy.find();

        if (!purchases.length) {
            return res.status(404).json({ message: 'No purchases found.' });
        }

        // Fetch additional details from Google Books API
        const bookDetailsPromises = purchases.map(async(purchase) => {
            // Check if googleId exists
            if (!purchase.googleId) {
                return {
                    ...purchase.toObject(),
                    googleBookDetails: null, // Set googleBookDetails to null if googleId is missing
                };
            }

            // Attempt to fetch details by googleId
            const googleIdResponse = await fetch(`https://www.googleapis.com/books/v1/volumes/${purchase.googleId}?key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A`);
            const googleIdData = await googleIdResponse.json();

            if (googleIdResponse.ok) {
                return {
                    ...purchase.toObject(),
                    googleBookDetails: googleIdData, // Use the data from googleId
                };
            } else {
                console.warn(`Failed to fetch details for googleId: ${purchase.googleId}. Attempting to fetch by ISBN.`);

                // Fallback to fetch by ISBN if googleId fetch fails
                if (!purchase.industryIdentifier || purchase.industryIdentifier.length === 0) {
                    return {
                        ...purchase.toObject(),
                        googleBookDetails: null, // Set to null if identifier is missing
                    };
                }

                const isbn = purchase.industryIdentifier[0]; // Get the first identifier
                const isbnResponse = await fetch(`https://www.googleapis.com/books/v1/volumes?q=isbn:${isbn}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A`);
                const isbnData = await isbnResponse.json();

                // Check if the response is okay and contains valid items
                if (isbnResponse.ok && isbnData.totalItems > 0) {
                    return {
                        ...purchase.toObject(),
                        googleBookDetails: isbnData.items[0], // Use the first item
                    };
                } else {
                    console.error(`ISBN not found for ${isbn}.`);
                    return {
                        ...purchase.toObject(),
                        googleBookDetails: null, // Set to null if both attempts fail
                    };
                }
            }
        });

        const detailedPurchases = await Promise.all(bookDetailsPromises);
        return res.status(200).json({ data: detailedPurchases });
    } catch (error) {
        console.error('Error fetching user purchases:', error);
        return res.status(500).json({ error: 'Error fetching user purchases' });
    }
});

// Update locationId for a specific book copy
app.put('/api/updateLocationId/:copyId', async (req, res) => {
    const { copyId } = req.params;
    const { locationId } = req.body;

    if (!locationId) {
        return res.status(400).json({ error: 'locationId is required' });
    }

    try {
        const book = await BookBuy.findOne({ 'copies._id': copyId });
        if (!book) {
            return res.status(404).json({ error: 'Book or copy not found' });
        }

        const copy = book.copies.id(copyId);
        if (!copy) {
            return res.status(404).json({ error: 'Copy not found in the book' });
        }

        copy.locationId = locationId;
        await book.save();

        res.status(200).json({ message: 'locationId updated successfully', book });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update locationId' });
    }
});



app.post('/api/importBooks', upload.single('file'), async (req, res) => {
    const results = [];
    const errors = [];
    const csvHeaders = [
        'title',
        'authors',
        'publisher',
        'publishedDate',
        'description',
        'pageCount',
        'categories',
        'language',
        'coverImage',
        'copyId',
        'bookLocation',
        'locationId',
        'availability',
        'status',
        'industryIdentifier',
        'epc',
    ];

    if (req.file) {
        try {
            const fileStream = fs.createReadStream(req.file.path, { encoding: 'utf8' });

            fileStream
                .pipe(csv({ headers: csvHeaders }))
                .on('data', (data) => {
                    // Filter out unexpected columns and sanitize data
                    const trimmedData = Object.fromEntries(
                        Object.entries(data)
                            .filter(([key]) => csvHeaders.includes(key)) // Keep only valid headers
                            .map(([key, value]) => [key, value?.trim() || '']) // Trim values
                    );

                    // Skip rows where all fields are empty
                    if (Object.values(trimmedData).some((value) => value)) {
                        results.push(trimmedData);
                    }
                })
                .on('end', async () => {
                    try {
                        console.log('Parsed CSV Data:', results);
                        await processBooks(results, errors);

                        fs.unlinkSync(req.file.path); // Delete the uploaded file

                        sendResponse(res, errors); // Send response with errors (if any)
                    } catch (error) {
                        console.error('Error processing books:', error.message);
                        res.status(500).json({
                            error: 'Failed to process books.',
                            details: error.message,
                        });
                    }
                })
                .on('error', (error) => {
                    console.error('Error parsing CSV:', error.message);
                    res.status(400).json({
                        error: 'Error parsing CSV file.',
                        details: error.message,
                    });
                });
        } catch (error) {
            console.error('Error handling file upload:', error.message);
            res.status(500).json({
                error: 'Error handling file upload.',
                details: error.message,
            });
        }
    } else {
        res.status(400).json({
            error: 'No valid input provided. Please upload a CSV file.',
        });
    }
});

function generateLocationId(isbn, title, authors, publishedDate, category, copyIndex = 1) {
    const lccCodes = {
        "Juvenile Fiction": "PZ",
        "Juvenile Nonfiction": "PZ",
        "Fiction": "PS",
        "Nonfiction": "PN",
        "Science": "Q",
        "Mathematics": "QA",
        "History": "D",
        "Biography & Autobiography": "CT",
        "Self-Help": "BF",
        "Religion": "BL",
        "Philosophy": "B",
        "Psychology": "BF",
        "Health & Fitness": "RA",
        "Computers": "QA76",
        "Business & Economics": "HF",
        "Education": "L",
        "Music": "M",
        "Art": "N",
        "Drama": "PN",
        "Poetry": "PN",
        "Travel": "G",
        "Sports & Recreation": "GV",
        "Cooking": "TX",
        "Crafts & Hobbies": "TT",
        "Gardening": "SB",
        "Medical": "R",
        "Law": "K",
        "Political Science": "J",
        "Social Science": "H",
        "True Crime": "HV",
        "Humor": "PN",
        "Fantasy": "PZ",
        "Science Fiction": "PZ",
        "Horror": "PZ",
        "Romance": "PS",
        "Mystery": "PS",
        "Thriller": "PS",
        "Adventure": "PZ",
        "Comics & Graphic Novels": "PN6728",
        "Parenting": "HQ",
        "Foreign Language Study": "P",
        "Reference": "Z",
        "Technology & Engineering": "T",
        "Performing Arts": "NX",
        "Philosophy & Religion": "B",
        "Pets": "SF",
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
    const userId = 'defaultUserId'; // Replace with a valid user ID if needed

    for (const book of books) {
        try {
            const requiredFields = [
                'title',
                'authors',
                'industryIdentifier',
                'copyId',
                'bookLocation',
                'epc',
            ];

            // Check for missing required fields
            const missingFields = requiredFields.filter((field) => !book[field] || book[field].trim() === '');
            if (missingFields.length > 0) {
                console.warn('Missing required fields:', book, 'Missing:', missingFields);
                errors.push({
                    error: 'Missing required fields',
                    book,
                    missingFields,
                });
                continue; // Skip this book if required fields are missing
            }

            const {
                title,
                authors,
                publisher,
                publishedDate,
                description,
                pageCount,
                categories,
                language,
                coverImage,
                industryIdentifier,
                copyId,
                bookLocation,
                availability,
                status,
                epc,
            } = book;

            console.log(`Processing book: ${title}, EPC: ${epc}`);

            if (!epc || epc.trim() === '') {
                console.warn(`Skipping book due to missing EPC: ${title}`);
                continue; // Skip books with missing EPC
            }

            // Sanitize and validate fields
            const isAvailable = availability?.toLowerCase() === 'true';
            const sanitizedStatus = ['borrowed', 'in return box', 'in library'].includes(status?.trim().toLowerCase())
                ? status.trim().toLowerCase()
                : 'in library'; // Default to "in library" if invalid
            const sanitizedPageCount = pageCount ? parseInt(pageCount, 10) : 0;

            // Determine the category for generating locationId
            const category = categories?.split(',')[0]?.trim() || 'Unknown';

            // Check if the book already exists in the database
            const existingBook = await BookBuy.findOne({
                title: title.trim(),
                authors: { $all: authors.split(',').map((a) => a.trim()) },
                industryIdentifier: { $in: [industryIdentifier.trim()] },
            });

            if (existingBook) {
                console.log(`Book found: ${existingBook.title}`);

                // Check if the copy already exists
                const existingCopy = existingBook.copies.find((copy) => copy.copyId === copyId);
                if (!existingCopy) {
                    console.log(`Adding new copy to existing book: ${title}`);

                    // Generate the locationId for the new copy
                    const locationId = generateLocationId(
                        industryIdentifier.trim(),
                        title.trim(),
                        authors.split(',').map((a) => a.trim()),
                        publishedDate,
                        category,
                        existingBook.copies.length + 1 // Next copy index
                    );

                    console.log(`New copy added with generated locationId: ${locationId}`);

                    existingBook.copies.push({
                        copyId: copyId?.trim(),
                        bookLocation: bookLocation?.trim(),
                        locationId: locationId, // Use the generated locationId
                        availability: isAvailable,
                        status: sanitizedStatus, // Use sanitized status
                        epc: epc?.trim(),
                    });

                } else {
                    console.log(`Duplicate copy found: ${copyId}. Not generating a new locationId.`);
                    // Update the existing copy's details without regenerating the locationId
                    existingCopy.bookLocation = bookLocation?.trim();
                    existingCopy.availability = isAvailable;
                    existingCopy.status = sanitizedStatus; // Use sanitized status
                    existingCopy.epc = epc?.trim();
                }

                // Save EPC information for this copy
                const epcResult = await saveEPC({
                    epc: epc?.trim(),
                    title: title.trim(),
                    author: authors.split(',').map((a) => a.trim()),
                    status: sanitizedStatus,
                    industryIdentifier: [industryIdentifier.trim()],
                });

                if (epcResult.duplicate) {
                    console.log(`Duplicate EPC skipped: ${epc}`);
                } else {
                    console.log(`EPC data created successfully for book: ${title}`);
                }

                // Update the quantity based on the number of unique copies
                existingBook.quantity = existingBook.copies.length;

                // Save the updated book
                await existingBook.save();
            } else {
                console.log(`Creating a new book entry: ${title}`);
                const locationId = generateLocationId(
                    industryIdentifier.trim(),
                    title.trim(),
                    authors.split(',').map((a) => a.trim()),
                    publishedDate,
                    category,
                    1 // First copy
                );

                console.log(`New book created with first copy locationId: ${locationId}`);

                const newBook = new BookBuy({
                    userid: userId,
                    industryIdentifier: [industryIdentifier.trim()],
                    title: title.trim(),
                    authors: authors.split(',').map((a) => a.trim()),
                    publisher: publisher?.trim() || '',
                    publishedDate: isValidDate(publishedDate) ? publishedDate.trim() : '',
                    description: description?.trim() || '',
                    pageCount: sanitizedPageCount, // Use sanitized pageCount
                    categories: categories ? categories.split(',').map((c) => c.trim()) : [],
                    language: language?.trim() || '',
                    coverImage: coverImage?.trim() || '',
                    purchaseDate: new Date(),
                    quantity: 1, // New book starts with one copy
                    copies: [
                        {
                            copyId: copyId?.trim(),
                            bookLocation: bookLocation?.trim(),
                            locationId: locationId, // Use the generated locationId
                            availability: isAvailable,
                            status: sanitizedStatus, // Use sanitized status
                            epc: epc?.trim(),
                        },
                    ],
                });

                // Save the new book
                await newBook.save();

                // Save EPC information for this copy
                const epcResult = await saveEPC({
                    epc: epc?.trim(),
                    title: title.trim(),
                    author: authors.split(',').map((a) => a.trim()),
                    status: sanitizedStatus,
                    industryIdentifier: [industryIdentifier.trim()],
                });

                if (epcResult.duplicate) {
                    console.log(`Duplicate EPC skipped: ${epc}`);
                } else {
                    console.log(`EPC data created successfully for book: ${title}`);
                }
            }
        } catch (error) {
            console.error('Error processing book:', book, error.message);
            errors.push({
                error: 'Failed to process book.',
                book,
                details: error.message,
            });
        }
    }
}
// Function to validate date format
function isValidDate(dateString) {
    const date = new Date(dateString);
    return !isNaN(date.getTime()); // Check if date is valid
}

// Function to send response to the client
function sendResponse(res, errors) {
    res.status(201).json({
        message: 'Books imported successfully!',
        errors: errors.length > 0 ? errors : undefined,
    });
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

        // If user details do not exist, create a new user with a generated library card
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
    console.log(`Server running on http://localhost:${PORT}`);
    await createDefaultAdmin();
});


// Catch-all route to redirect to index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});