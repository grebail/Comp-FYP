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
 // Define events to populate in the database
 const events = [
    {
        eventId: 'event-gatsby',
        title: 'The Great Gatsby',
        venue: 'Central Library, Room 101',
        time: 'March 15, 2025, 3:00 PM',
        eventLink: 'https://example.com/gatsby-reading',
    },
    {
        eventId: 'event-writing-workshop',
        title: 'Writing Workshop',
        venue: 'Central Library, Room 202',
        time: 'March 20, 2025, 1:00 PM',
        eventLink: 'https://example.com/writing-workshop',
    },
    {
        eventId: 'event-author-meet',
        title: 'Author Meet and Greet',
        venue: 'Central Library, Room 303',
        time: 'April 10, 2025, 5:00 PM',
        eventLink: 'https://example.com/author-meet',
    },
    {
        eventId: 'event-digital-literacy',
        title: 'Digital Literacy Workshop',
        venue: 'Central Library, Room 404',
        time: 'April 15, 2025, 2:00 PM',
        eventLink: 'https://example.com/digital-literacy',
    },
];
    
    // Function to populate the database
    async function populateEvents() {
    try {
        // Clear the existing events
        await Event.deleteMany({});
        console.log('Existing events cleared.');
    
        // Add new events
        await Event.insertMany(events);
        console.log('Events added successfully.');
    
      
    } catch (error) {
        console.error('Error populating events:', error);
       
    }
    }
    
// API to handle booking
app.post('/api/bookEvent', async (req, res) => {
    try {
        const { eventName, userName, userEmail } = req.body;

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

        // Sanitize the email address for use as a key in the Map
        const sanitizedEmail = userEmail.replace(/\./g, '[dot]');

        // Check if the user is already registered
        if (event.registeredUsers.has(sanitizedEmail)) {
            return res.status(400).json({ error: 'User already registered for this event.' });
        }

        // Add the sanitized email and user name to the registeredUsers map
        event.registeredUsers.set(sanitizedEmail, userName);

        // Save the updated event
        await event.save();

        console.log(`User ${userName} registered for event ${event.title}`);

        // Send confirmation email
        await sendBookingConfirmationEmail({ eventName, userName, userEmail });

        res.status(200).json({ message: 'Booking confirmed, email sent, and user saved to the database.' });
    } catch (error) {
        console.error('Error in /api/bookEvent:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Run the function
populateEvents();

// Utility function to format date in UTC
function formatDateToUTC(date) {
    return new Date(date).toUTCString(); // Converts date to UTC string format
}

// Function to send email using SendGrid
async function sendEmail(userDetails) {
    try {
        const fromAddress = 'abbichiu@gmail.com'; // Sender email
        const toAddress = userDetails.email;     // Recipient email from user details

        if (!toAddress) {
            throw new Error('Recipient address is required.');
        }

        // Compose the email including the current loans
        let loanDetailsText = 'Current Loans:\n\n';
        userDetails.currentLoans.forEach((loan, index) => {
            loanDetailsText += `Loan ${index + 1}:\n`;
            loanDetailsText += `Title: ${loan.details.title}\n`;
            loanDetailsText += `Authors: ${loan.details.authors.join(', ')}\n`;
            loanDetailsText += `Borrow Date: ${formatDateToUTC(loan.details.borrowDate)}\n`; // Convert to UTC
            loanDetailsText += `Due Date: ${formatDateToUTC(loan.details.dueDate)}\n`;     // Convert to UTC
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
            subject: 'Loan Due Reminder: Your Current Loan Details',
            text: emailContent, // Plain text body
            html: `<pre>${emailContent}</pre>`, // HTML body (optional for better formatting)
        };

        // Send email using SendGrid
        const response = await sgMail.send(msg);

        console.log(`Email sent successfully to ${toAddress}. Response:`, response);
        return response;
    } catch (error) {
        console.error('Error sending email:', error.response ? error.response.body : error.message);
        throw new Error('Error sending email');
    }
}

// Scheduled task to send reminder emails
cron.schedule('0 9 * * *', async () => { // Runs every day at 9 AM
    console.log('Cron job started at:', new Date());
    try {
        const today = new Date();
        const threeDaysFromNow = new Date(today);
        threeDaysFromNow.setUTCDate(today.getUTCDate() + 3); // Use UTC dates

        // Fetch users with loans due in the next 3 days
        const usersWithLoans = await UserDetails.find({
            'currentLoans.details.dueDate': {
                $gte: today.toISOString(), // Use ISO string for comparison
                $lt: threeDaysFromNow.toISOString(),
            },
        });

        if (usersWithLoans.length === 0) {
            console.log('No users with loans due in the next 3 days.');
            return;
        }

        for (const user of usersWithLoans) {
            await sendEmail(user);
        }
    } catch (error) {
        console.error('Error sending scheduled emails:', error.message);
    }
    console.log('Cron job finished at:', new Date());
});

// Route to manually send an email
app.post('/send-email', async (req, res) => {
    try {
        // Fetch user details from the database (modify query as needed)
        const userDetails = await UserDetails.findOne(); // Fetch the first user for demonstration

        if (!userDetails) {
            return res.status(404).send('No user found.');
        }

        // Send email
        await sendEmail(userDetails);

        res.status(200).send('Email sent successfully!');
    } catch (error) {
        console.error('Error sending email:', error.message);
        res.status(500).send('Error sending email');
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
                ? `http://localhost:10000/index_logined.html?userid=${user._id}`
                : `http://localhost:10000/index_userlogined.html?userid=${user._id}`;

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
// Create a new admin book
// Create a new admin book
app.post('/api/admin_books', authenticateToken, async (req, res) => {
    const { isbn, bookLocation, locationId, availability, noOfCopy } = req.body;

    // Input validation
    if (!isbn || !bookLocation || !locationId || isNaN(noOfCopy) || noOfCopy < 1) {
        return res.status(400).json({ error: 'Missing or invalid required fields' });
    }

    try {
        // Fetch book details from Google Books API
        const googleBooksResponse = await axios.get(
            `https://www.googleapis.com/books/v1/volumes?q=isbn:${isbn}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A`
        );
        const bookData = googleBooksResponse.data;

        if (bookData.totalItems === 0) {
            return res.status(404).json({ error: 'Book not found in Google Books API' });
        }

        const bookInfo = bookData.items[0].volumeInfo;

        // Create the new AdminBook entries
        const adminBooks = [];
        const copies = []; // Initialize copies array for BookBuy

        for (let i = 0; i < noOfCopy; i++) {
            const newAdminBook = new AdminBook({
                industryIdentifier: [isbn],
                googleId: bookInfo.id,
                bookLocation,
                locationId,
                availability,
                noOfCopy: 1, // Each copy is treated as a single entry
                title: bookInfo.title,
                authors: bookInfo.authors || [], // Ensure authors is stored as an array
                publishedDate: bookInfo.publishedDate ? new Date(bookInfo.publishedDate) : null,
                categories: bookInfo.categories || [] // Fetch categories from Google Books API
            });

            const savedAdminBook = await newAdminBook.save();
            adminBooks.push({
                copyId: savedAdminBook._id,
                adminBook: savedAdminBook
            });

            // Add each copy's details to the copies array
            copies.push({
                copyId: savedAdminBook._id,
                bookLocation,
                locationId: `${locationId}.${i + 1}`, // Append copy index to location ID
                availability,
                status: 'in library', // Default status
                epc: null // Initially set EPC to null
            });
        }

        // Check if a corresponding entry exists in BookBuy
        let bookBuy;
        const existingBookBuy = await BookBuy.findOne({ industryIdentifier: { $in: [isbn] } });

        if (existingBookBuy) {
            // If the book already exists, add the new copies to the copies array
            existingBookBuy.copies.push(...copies);
            bookBuy = await existingBookBuy.save();
        } else {
            // Create a new corresponding entry in BookBuy with the copies array
            bookBuy = await BookBuy.create({
                userid: req.user.id, // Assuming you have user information in the request
                googleId: bookInfo.id,
                industryIdentifier: [isbn],
                title: bookInfo.title,
                authors: bookInfo.authors || [], // Ensure authors is stored as an array
                publisher: bookInfo.publisher,
                publishedDate: bookInfo.publishedDate,
                description: bookInfo.description,
                categories: bookInfo.categories || [],
                coverImage: bookInfo.imageLinks ? bookInfo.imageLinks.thumbnail : null,
                copies: copies, // Include copies array
            });
        }

        // Invoke the assignEPCsToExistingCopies function
        const bookTitle = bookBuy.title;
        const bookAuthors = bookBuy.authors;
        await assignEPCsToExistingCopies(bookTitle, bookAuthors);

        // Return the created adminBooks in the response
        res.status(201).json({
            adminBooks: adminBooks.map(book => ({
                industryIdentifier: book.adminBook.industryIdentifier,
                copyId: book.copyId,
                bookLocation: book.adminBook.bookLocation,
                locationId: book.adminBook.locationId,
                availability: book.adminBook.availability,
                noOfCopy: book.adminBook.noOfCopy,
                title: book.adminBook.title,
                authors: book.adminBook.authors, // Return authors as an array
                publishedDate: book.adminBook.publishedDate,
                categories: book.adminBook.categories // Include categories in response
            }))
        });
    } catch (error) {
        console.error('Error adding admin book:', error);
        res.status(500).json({ error: 'Failed to add admin book.', details: error.message });
    }
});
  
// Get all admin books
app.get('/api/admin_books', authenticateToken, async(req, res) => {
    try {
        const adminBooks = await AdminBook.find();
        res.status(200).json(adminBooks.map(book => ({
            _id: book._id,
            isbn: book.industryIdentifier[0] || 'N/A',
            industryIdentifier: book.industryIdentifier,// Include the full array if needed
            googleId: book.googleId,

            bookLocation: book.bookLocation,
            locationId: book.locationId,
            availability: book.availability,
            noOfCopy: book.noOfCopy,
            title: book.title,
            author: book.authors,
            publishedDate: book.publishedDate,
            categories: book.categories // Include categories in response
        })));
    } catch (error) {
        console.error('Error retrieving admin books:', error);
        res.status(500).json({ error: 'Failed to retrieve admin books.' });
    }
});



// Update an admin book copy
app.put('/api/admin_books/:copyId', authenticateToken, async(req, res) => {
    const copyId = req.params.copyId.trim().replace(/\s+/g, '');
    const { bookLocation, locationId, availability } = req.body;

    // Input validation
    if (!bookLocation || !locationId || availability === undefined) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        // Find the corresponding AdminBook by copyId
        const adminBook = await AdminBook.findById(copyId);

        if (!adminBook) {
            return res.status(404).json({ error: 'Admin book not found' });
        }

        // Find the corresponding BookBuy entry for the specific copyId
        const existingBookBuy = await BookBuy.findOne({ 'copies.copyId': copyId });

        if (!existingBookBuy) {
            return res.status(404).json({ error: 'Book copy not found in BookBuy' });
        }

        // Find the specific copy to update using the copyId
        const copyToUpdate = existingBookBuy.copies.find(copy => copy.copyId === copyId);
        if (copyToUpdate) {
            // Update fields in the copy
            copyToUpdate.bookLocation = bookLocation;
            copyToUpdate.locationId = locationId;
            copyToUpdate.availability = availability;

            await existingBookBuy.save(); // Save the updated entry

            // Update the AdminBook fields
            adminBook.bookLocation = bookLocation;
            adminBook.locationId = locationId;
            adminBook.availability = availability;
            await adminBook.save();

            res.json(copyToUpdate); // Send back the updated copy
        } else {
            return res.status(404).json({ error: 'Copy not found in the BookBuy entry' });
        }
    } catch (error) {
        console.error('Error updating admin book copy:', error.message);
        res.status(500).json({ error: 'Failed to update admin book copy' });
    }
});

// Delete an admin book copy
app.delete('/api/admin_books/:copyId', authenticateToken, async(req, res) => {
    const copyId = req.params.copyId.trim().replace(/\s+/g, '');

    try {
        // Find the corresponding AdminBook by copyId
        const adminBook = await AdminBook.findById(copyId);

        if (!adminBook) {
            return res.status(404).json({ error: 'Admin book not found' });
        }

        // Find the corresponding BookBuy entry for the specific copyId
        const existingBookBuy = await BookBuy.findOne({ 'copies.copyId': copyId });

        if (!existingBookBuy) {
            return res.status(404).json({ error: 'Book copy not found in BookBuy' });
        }

        // Remove the specific copy from the copies array
        existingBookBuy.copies = existingBookBuy.copies.filter(copy => copy.copyId !== copyId);

        await existingBookBuy.save(); // Save the updated entry

        // Also delete the corresponding admin book entry
        await AdminBook.deleteOne({ _id: copyId });

        // Optionally, if no copies remain, you may choose to delete the BookBuy entry
        if (existingBookBuy.copies.length === 0) {
            await BookBuy.deleteOne({ industryIdentifier: existingBookBuy.industryIdentifier });
        }

        res.sendStatus(204); // No Content
    } catch (error) {
        console.error('Error deleting admin book copy:', error.message);
        res.status(500).json({ error: 'Failed to delete admin book copy.' });
    }
});

// Route to serve the book administration page
app.get('/book_admin.html', authenticateToken, async(req, res) => {
    try {
        // Fetch the user role from the database
        const user = await User.findById(req.user.id).select('role');

        // Check if the user's role is 'librarian'
        if (user.role !== 'librarian') {
            return res.status(403).json({ message: 'Forbidden: You do not have access to this page.' });
        }

        // If the user is a librarian, send the book administration page
        res.sendFile(path.join(__dirname, 'public', 'book_admin.html'));
    } catch (error) {
        console.error('Error fetching user role:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

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
// Configure multer for temporary file storage
const upload = multer({ dest: 'uploads/' });

// API endpoint to import books from CSV
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
                const trimmedData = Object.fromEntries(
                    Object.entries(data).map(([key, value]) => [key, value?.trim() || ''])
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
        
                    res.status(201).json({ message: 'Books imported successfully!', errors });
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
// Process books from parsed CSV data
async function processBooks(books, errors) {
    const userId = 'defaultUserId'; // Replace with a valid user ID if needed

    for (const book of books) {
        try {
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

            // Find existing book in the database
            const existingBook = await BookBuy.findOne({
                title: title.trim(),
                authors: { $all: authors.split(',').map((a) => a.trim()) },
                industryIdentifier: { $in: [industryIdentifier.trim()] },
            });

            const copy = {
                copyId: copyId?.trim(),
                bookLocation: bookLocation?.trim(),
                locationId: generateLocationId(
                    industryIdentifier,
                    title,
                    authors.split(',').map((a) => a.trim()),
                    publishedDate,
                    categories.split(',')[0], // Use the first category
                    1 // Copy index is irrelevant for updates
                ),
                availability: availability?.toLowerCase() === 'true',
                status: status?.trim() || 'in library',
                epc: epc?.trim(),
            };

            if (existingBook) {
                console.log(`Book found: ${existingBook.title}`);

                // Check if the copy already exists
                const existingCopyIndex = existingBook.copies.findIndex(c => c.copyId === copy.copyId);

                if (existingCopyIndex > -1) {
                    // Update the existing copy with new values
                    console.log(`Updating existing copy with ID ${copy.copyId}`);
                    existingBook.copies[existingCopyIndex] = {
                        ...existingBook.copies[existingCopyIndex],
                        ...copy, // Merge existing values with updated ones
                    };
                } else {
                    // Add a new copy if it doesn't exist
                    console.log(`Adding new copy with ID ${copy.copyId}`);
                    existingBook.copies.push(copy);
                    existingBook.quantity += 1;
                }

                // Update the book's general information with the latest values
                existingBook.publisher = publisher;
                existingBook.publishedDate = publishedDate;
                existingBook.description = description;
                existingBook.pageCount = pageCount;
                existingBook.categories = categories.split(',').map((c) => c.trim());
                existingBook.language = language;
                existingBook.coverImage = coverImage;

                await existingBook.save();
            } else {
                console.log(`Creating a new book entry: ${title}`);
                const newBook = new BookBuy({
                    userid: userId,
                    industryIdentifier: [industryIdentifier.trim()],
                    title: title.trim(),
                    authors: authors.split(',').map((a) => a.trim()),
                    publisher,
                    publishedDate,
                    description,
                    pageCount,
                    categories: categories.split(',').map((c) => c.trim()),
                    language,
                    coverImage,
                    copies: [copy],
                    quantity: 1,
                });
                await newBook.save();
            }
        } catch (error) {
            console.error('Error processing book:', book, error.message);
            errors.push({ error: 'Failed to process book.', book, details: error.message });
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
// API endpoint to get loan details for a specific user
app.get('/api/userBorrowsDetails', authenticateToken, async (req, res) => {
    const { userid } = req.query;

    if (!userid || userid !== req.user.id) {
        return res.status(403).json({ error: 'You do not have permission to view this borrow history.' });
    }

    try {
        // Fetch only the books that are currently borrowed (not returned)
        const borrows = await UserBorrow.find({ userid: userid, returned: false });

        // Map the borrows to include additional details
        const detailedBorrows = borrows.map(borrow => ({
            _id: borrow._id,
            title: borrow.title,
            authors: borrow.authors,
            availability: borrow.availability,
            borrowDate: borrow.borrowDate,
            dueDate: borrow.dueDate,
            comments: borrow.comments,
            copyId: borrow.copyId,
            googleId: borrow.googleId,
            industryIdentifier: borrow.industryIdentifier,
            publishedDate: borrow.publishedDate,
            publisher: borrow.publisher,
            returned: borrow.returned,
            userid: borrow.userid,
        }));

        res.json(detailedBorrows);
    } catch (error) {
        console.error('Error fetching borrow history:', error);
        res.status(500).json({ error: 'Failed to fetch borrow history.' });
    }
});


// Route to serve the Google verification file
app.get('/google56342aab9c608962.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'google56342aab9c608962.html'));
});
// API endpoint to save user details

const updateCurrentLoans = async (userId) => {
    try {
        // Fetch borrow records where at least one copy is not returned
        const borrows = await UserBorrow.find({ userid: userId, "copies.returned": false });

        console.log(`[DEBUG] Fetched borrows for userId ${userId}:`, borrows);

        // Flatten the `copies` array and map relevant data
        const currentLoans = borrows.flatMap(borrow => {
            return borrow.copies
                .filter(copy => !copy.returned) // Include only non-returned copies
                .map(copy => ({
                    borrowId: borrow._id,
                    details: {
                        title: borrow.title,
                        authors: borrow.authors,
                        copyId: copy.copyId,
                        bookLocation: copy.bookLocation || 'Unknown',
                        locationId: copy.locationId || 'Unknown',
                        availability: copy.availability || false,
                        borrowDate: copy.borrowedDate,
                        dueDate: copy.dueDate,
                        returned: copy.returned,
                        industryIdentifier: borrow.industryIdentifier,
                        publishedDate: borrow.publishedDate,
                        publisher: borrow.publisher,
                    },
                }));
        });

        console.log(`[DEBUG] Mapped currentLoans for userId ${userId}:`, currentLoans);

        return currentLoans;
    } catch (error) {
        console.error('[ERROR] Failed to fetch or map borrows:', error.message);
        throw new Error('Failed to update current loans.');
    }
};
// API endpoint to save user details
app.post('/api/userDetails', authenticateToken, async (req, res) => {
    const { userId, name, email, phone, libraryCard } = req.body;

    if (!userId || !name || !email || !phone || !libraryCard) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        let userDetails = await UserDetails.findOne({ userId });

        if (userDetails) {
            // Fetch current loans and update existing user details
            const currentLoans = await updateCurrentLoans(userId);

            console.log(`[DEBUG] Updating currentLoans for userId ${userId}:`, currentLoans);

            userDetails.name = name;
            userDetails.email = email;
            userDetails.phone = phone;
            userDetails.libraryCard = libraryCard;
            userDetails.currentLoans = currentLoans;

            await userDetails.save();
            return res.status(200).json({ message: 'User details updated successfully.' });
        } else {
            // Fetch current loans for a new userDetails document
            const currentLoans = await updateCurrentLoans(userId);

            console.log(`[DEBUG] Creating new userDetails with currentLoans for userId ${userId}:`, currentLoans);

            // Create new user details
            userDetails = new UserDetails({
                userId,
                name,
                email,
                phone,
                libraryCard,
                currentLoans, // Assign current loans fetched from UserBorrow
            });

            await userDetails.save();
            return res.status(201).json({ message: 'User details saved successfully.', userDetails });
        }
    } catch (error) {
        console.error('[ERROR] Failed to save user details:', error.message);
        return res.status(500).json({ error: error.message });
    }
});
// Get userDetails
// Get userDetails
app.get('/api/userDetails', authenticateToken, async (req, res) => {
    const { userid } = req.query;

    if (!userid) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    try {
        let userDetails = await UserDetails.findOne({ userId: userid }).populate('currentLoans.borrowId');

        // If UserDetails does not exist, create a new one
        if (!userDetails) {
            console.log(`[INFO] UserDetails not found for userId: ${userid}. Creating a new document.`);

            userDetails = new UserDetails({
                userId: userid,
                name: '',
                email: '',
                phone: '',
                libraryCard: '',
                currentLoans: [],
            });

            await userDetails.save();
        }

        // Update the currentLoans field
        userDetails.currentLoans = await updateCurrentLoans(userid);
        await userDetails.save();

        console.log(`[DEBUG] Updated currentLoans for userId ${userid}:`, userDetails.currentLoans);

        return res.status(200).json(userDetails);
    } catch (error) {
        console.error('[ERROR] Failed to fetch user details:', error.message);
        return res.status(500).json({ error: error.message });
    }
});
// API endpoint to get loan details for a specific user
// API endpoint to get loan details for a specific user
app.get('/api/userBorrowsDetails', authenticateToken, async (req, res) => {
    const { userid } = req.query;

    // Validate the user ID and permissions
    if (!userid || userid !== req.user.id) {
        return res.status(403).json({ error: 'You do not have permission to view this borrow history.' });
    }

    try {
        // Fetch all borrow records for the user where copies are not returned
        const borrows = await UserBorrow.find({ userid, "copies.returned": false });

        console.log(`[DEBUG] Fetched borrows for userId ${userid}:`, borrows);

        // Map the borrow records to include relevant details
        const detailedBorrows = borrows.flatMap(borrow => {
            return borrow.copies
                .filter(copy => !copy.returned) // Only include copies that are not returned
                .map(copy => ({
                    _id: borrow._id,
                    title: borrow.title,
                    authors: borrow.authors,
                    copyId: copy.copyId,
                    bookLocation: copy.bookLocation || 'Unknown',
                    locationId: copy.locationId || 'Unknown',
                    borrowedDate: copy.borrowedDate,
                    dueDate: copy.dueDate,
                    returned: copy.returned,
                    industryIdentifier: borrow.industryIdentifier,
                    publishedDate: borrow.publishedDate,
                    publisher: borrow.publisher,
                    userid: borrow.userid,
                }));
        });

        // Return the detailed borrow records
        return res.json(detailedBorrows);
    } catch (error) {
        console.error('[ERROR] Failed to fetch borrow history:', error.message);
        return res.status(500).json({ error: 'Failed to fetch borrow history.' });
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

// Start server and create default admin
app.listen(PORT, async() => {
    console.log(`Server running on http://localhost:${PORT}`);
    await createDefaultAdmin();
});


// Catch-all route to redirect to index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});