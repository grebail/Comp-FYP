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
// Utility function to format date in UTC
function formatDateToUTC(date) {
    return new Date(date).toUTCString(); // Converts date to UTC string format
}

// Function to send email using SendGrid
async function sendEmail(userDetails, detailedLoans) {
    try {
        const fromAddress = 'abbichiu@gmail.com'; // Sender email
        const toAddress = userDetails.email;          // Recipient email from user details

        if (!toAddress) {
            throw new Error('Recipient address is required.');
        }

        // Compose the email with the current loans
        let loanDetailsText = 'Current Loans:\n\n';
        detailedLoans.forEach((loan, index) => {
            loanDetailsText += `Loan ${index + 1}:\n`;
            loanDetailsText += `Title: ${loan.title}\n`;
            loanDetailsText += `Authors: ${loan.authors.join(', ')}\n`;
            loanDetailsText += `Borrow Date: ${formatDateToUTC(loan.borrowedDate)}\n`;
            loanDetailsText += `Due Date: ${formatDateToUTC(loan.dueDate)}\n`;
            loanDetailsText += `Returned: ${loan.returned ? 'Yes' : 'No'}\n\n`;
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

        console.log(`Email sent successfully to: ${toAddress}`);
        return response;
    } catch (error) {
        console.error('Error sending email to:', userDetails.email, error.response ? error.response.body : error.message);
        throw new Error('Error sending email');
    }
}

// Scheduled task to send reminder emails
cron.schedule('0 9 * * *', async () => { // Runs every day at 9 AM
    console.log('Cron job started at:', new Date());
    try {
        const today = new Date();
        const threeDaysFromNow = new Date(today);
        threeDaysFromNow.setUTCDate(today.getUTCDate() + 3);
        threeDaysFromNow.setUTCHours(23, 59, 59, 999); // Include the entire last day

        // Fetch all users
        const allUsers = await UserDetails.find();
        if (allUsers.length === 0) {
            console.log('Default admin account already exists.');
            return;
        }

        // Iterate over each user and fetch loans
        for (const userDetails of allUsers) {
            const userBorrows = await UserBorrow.find({
                userid: userDetails.userId,
                'copies.returned': false,
                'copies.dueDate': {
                    $gte: today.toISOString(),
                    $lt: threeDaysFromNow.toISOString(),
                },
            });

            // Prepare loan details for the user
            const detailedLoans = userBorrows.flatMap((borrow) =>
                borrow.copies
                    .filter((copy) => !copy.returned && copy.dueDate >= today && copy.dueDate < threeDaysFromNow)
                    .map((copy) => ({
                        title: borrow.title,
                        authors: borrow.authors,
                        borrowedDate: copy.borrowedDate,
                        dueDate: copy.dueDate,
                        returned: copy.returned,
                    }))
            );

            if (detailedLoans.length === 0) {
                console.log(`No loans due for user: ${userDetails.email}. Skipping.`);
                continue;
            }

            // Send email to the user
            try {
                await sendEmail(userDetails, detailedLoans);
            } catch (error) {
                console.error(`Failed to send email to: ${userDetails.email}`, error.message);
            }
        }

        console.log('Emails sent to all users with pending loans.');
    } catch (error) {
        console.error('Error sending scheduled emails:', error.message);
    }

    console.log('Cron job finished at:', new Date());
});

// Route to manually send an email
app.post('/send-email', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).send('Email is required to send the message.');
        }

        // Fetch user details by email
        const userDetails = await UserDetails.findOne({ email });

        if (!userDetails) {
            return res.status(404).send('No user found with the given email.');
        }

        // Fetch loans for the user
        const userBorrows = await UserBorrow.find({ userid: userDetails.userId, "copies.returned": false });

        const detailedLoans = userBorrows.flatMap(borrow => {
            return borrow.copies
                .filter(copy => !copy.returned)
                .map(copy => ({
                    title: borrow.title,
                    authors: borrow.authors,
                    borrowedDate: copy.borrowedDate,
                    dueDate: copy.dueDate,
                    returned: copy.returned,
                }));
        });

        if (detailedLoans.length === 0) {
            return res.status(404).send('No current loans found for the user.');
        }

        // Send the email
        await sendEmail(userDetails, detailedLoans);

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
                    // Mark as unavailable and add borrowing details
                    copy.availability = false;
                    copy.borrowedDate = new Date();
                    copy.dueDate = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000); // 14 days from today
                    copy.returned = false;
                    borrowedCopies.push(copy);
                } else {
                    unavailableCopies.push(copy.copyId);
                }
            }
        });

        // Save the updated book document
        await book.save();

        // Handle unavailable copies
        if (unavailableCopies.length > 0) {
            return res.status(400).json({
                error: 'Some copies are unavailable.',
                unavailableCopies
            });
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
                    availability: copy.availability,
                    dueDate: copy.dueDate,
                    returned: copy.returned,
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
                    availability: copy.availability,
                    dueDate: copy.dueDate,
                    returned: copy.returned,
                })),
            });
        }

        // Save the borrow record
        await userBorrow.save();

        // Respond with redirect URL including valid copy IDs
        res.status(200).json({
            message: 'Copies borrowed successfully.',
            borrowedCopies,
            redirectUrl: `user_borrow_copy.html?userid=${userid}&isbn=${isbn}&copies=${copiesToBorrow.join(',')}`
        });
    } catch (error) {
        console.error('Error borrowing copies:', error);
        res.status(500).json({ error: error.message || 'Internal server error.' });
    }
});
//Update API for Returning a Copy
app.put('/api/userBorrows/:borrowRecordId/copies/:copyId/return', authenticateToken, async (req, res) => {
    const { borrowRecordId, copyId } = req.params;

    try {
        // Update the UserBorrow collection
        const userBorrow = await UserBorrow.findById(borrowRecordId);
        if (!userBorrow) {
            return res.status(404).json({ error: 'Borrow record not found' });
        }

        const userCopy = userBorrow.copies.find(copy => copy.copyId === copyId);
        if (!userCopy) {
            return res.status(404).json({ error: 'Copy not found in UserBorrow record.' });
        }

        if (userCopy.returned) {
            return res.status(400).json({ error: 'This copy has already been returned.' });
        }

        userCopy.returned = true;
        userCopy.availability= true;  
        await userBorrow.save();

        // Update the BookBuy collection
        const book = await BookBuy.findOne({ industryIdentifier: userBorrow.industryIdentifier });
        if (!book) {
            return res.status(404).json({ error: 'Book not found in BookBuy collection.' });
        }

        const bookCopy = book.copies.find(copy => copy.copyId === copyId);
        if (!bookCopy) {
            return res.status(404).json({ error: 'Copy not found in BookBuy collection.' });
        }

        bookCopy.availability = true;
        bookCopy.returned = true;
        bookCopy.borrowedDate = null;
        bookCopy.dueDate = null;

        await book.save();

        res.status(200).json({ message: 'Copy returned successfully.' });
    } catch (error) {
        console.error('Error returning copy:', error);
        res.status(500).json({ error: 'Failed to return the copy.' });
    }
});
//Update API for Borrowing Again
app.put('/api/userBorrows/:borrowRecordId/copies/:copyId/borrow-again', authenticateToken, async (req, res) => {
    const { borrowRecordId, copyId } = req.params;

    try {
        // Update the UserBorrow collection
        const userBorrow = await UserBorrow.findById(borrowRecordId);
        if (!userBorrow) {
            return res.status(404).json({ error: 'Borrow record not found' });
        }

        const userCopy = userBorrow.copies.find(copy => copy.copyId === copyId);
        if (!userCopy) {
            return res.status(404).json({ error: 'Copy not found in UserBorrow record.' });
        }

        if (!userCopy.returned) {
            return res.status(400).json({ error: 'This copy is already borrowed.' });
        }

        userCopy.returned = false;
        userCopy.availability = false;
        await userBorrow.save();

        // Update the BookBuy collection
        const book = await BookBuy.findOne({ industryIdentifier: userBorrow.industryIdentifier });
        if (!book) {
            return res.status(404).json({ error: 'Book not found in BookBuy collection.' });
        }

        const bookCopy = book.copies.find(copy => copy.copyId === copyId);
        if (!bookCopy) {
            return res.status(404).json({ error: 'Copy not found in BookBuy collection.' });
        }

        bookCopy.availability = false;
        bookCopy.returned = false;
        bookCopy.borrowedDate = new Date(); // Set the new borrowed date
        bookCopy.dueDate = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000); // Set due date 14 days from now

        await book.save();

        res.status(200).json({ message: 'Copy borrowed again successfully.' });
    } catch (error) {
        console.error('Error borrowing copy again:', error);
        res.status(500).json({ error: 'Failed to borrow the copy again.' });
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
                ? `https://comp-fyp.onrender.com/index_logined.html?userid=${user._id}`
                : `https://comp-fyp.onrender.com/index_userlogined.html?userid=${user._id}`;

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

        let books = response.data.items || [];
books = books.slice(0, 40);
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
app.get('/api/books', authenticateToken, async (req, res) => {
    if (req.user.role !== 'librarian') return res.sendStatus(403);

    const search = req.query.q;

    try {
        // Fetch books from Google Books API with a maximum of 40 results
        const response = await axios.get(`https://www.googleapis.com/books/v1/volumes?q=${search}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A&maxResults=40`);

        // Filter books with ISBN and limit to 40
        let books = response.data.items || [];
        books = books.filter(book => {
            const industryIdentifiers = book.volumeInfo.industryIdentifiers || [];
            return industryIdentifiers.some(identifier =>
                identifier.type === 'ISBN_10' || identifier.type === 'ISBN_13'
            );
        }).slice(0, 40);

        // Clear the database before saving new books
        await Book.deleteMany({});

        // Save filtered books to the database
        for (const book of books) {
            const industryIdentifiers = book.volumeInfo.industryIdentifiers || [];
            const industryIdentifier = industryIdentifiers.find(identifier =>
                identifier.type === 'ISBN_10' || identifier.type === 'ISBN_13'
            );

            const newBook = new Book({
                googleId: book.id,
                industryIdentifier: industryIdentifier ? industryIdentifier.identifier : 'N/A',
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

        // Send the filtered books (max 40) as the response
        res.json({
            data: books
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
        const googleBooksResponse = await axios.get(`https://www.googleapis.com/books/v1/volumes?q=isbn:${isbn}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A`);
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
                locationId,
                availability
            });
        }

        // Check if a corresponding entry exists in BookBuy
        const existingBookBuy = await BookBuy.findOne({ industryIdentifier: [isbn] });

        if (existingBookBuy) {
            // If the book already exists, add the new copies to the copies array
            existingBookBuy.copies.push(...copies);
            await existingBookBuy.save();
        } else {
            // Create a new corresponding entry in BookBuy with the copies array
            const newBookBuy = new BookBuy({
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
            await newBookBuy.save(); // Save the new book to the BookBuy collection
        }

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
// An endpoint to update inserted book copy

app.put('/api/updatePurchase/:copyId', authenticateToken, async (req, res) => {
    const { copyId } = req.params; // Extract copyId from the URL path
    const updateData = req.body; // Extract the fields to update from the request body

    // Validate request parameters
    if (!copyId) {
        return res.status(400).json({ error: 'Missing copyId.' });
    }

    try {
        // Find and update the specific copy within the copies array
        const updateResult = await BookBuy.updateOne(
            { 'copies.copyId': copyId }, // Match the specific copyId in the copies array
            {
                $set: {
                    'copies.$.bookLocation': updateData.bookLocation, // Update the bookLocation
                    'copies.$.locationId': updateData.locationId,     // Update the locationId
                    'copies.$.availability': updateData.availability, // Update availability
                },
            }
        );

        if (updateResult.matchedCount === 0) {
            return res.status(404).json({ error: 'Copy not found.' });
        }

        res.json({ message: 'Copy updated successfully.' });
    } catch (error) {
        console.error('Error updating copy:', error);
        res.status(500).json({ error: 'Failed to update copy.' });
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




// API endpoint to import books from CSV
const upload = multer({ dest: 'uploads/' }); // Temporary file storage


// API endpoint to import books from CSV
app.post('/api/importBooks', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded.' });
        }

        const results = [];
        const errors = [];

        fs.createReadStream(req.file.path)
            .pipe(csv({ separator: ',' }))
            .on('data', (data) => {
                results.push(data);
            })
            .on('end', async () => {
                try {
                    await processBooks(results, errors);
                    fs.unlinkSync(req.file.path); // Clean up uploaded file
                    res.json({ message: 'Books imported successfully.', errors });
                } catch (err) {
                    console.error('Error processing books:', err);
                    res.status(500).json({ error: 'Failed to process books.' });
                }
            })
            .on('error', (error) => {
                console.error('Error parsing CSV:', error);
                res.status(400).json({ error: 'Error parsing CSV file.' });
            });
    } catch (err) {
        console.error('Error importing books:', err);
        res.status(500).json({ error: 'An unexpected error occurred.' });
    }
});

async function processBooks(books, errors) {
    const userId = 'defaultUserId'; // Replace with a valid user ID if needed

    for (const book of books) {
        const {
            googleId, // Informational, not used for duplicate checks
            title,
            authors,
            publisher,
            publishedDate,
            description,
            pageCount,
            categories,
            language,
            coverImage,
            copies, // Optional field
            industryIdentifier // Used for duplicate checking
        } = book;

        // Validate required fields
        if (!title) {
            errors.push({ error: 'Missing title for a book.', book });
            continue;
        }

        // Allow flexible formats for publishedDate (year-only, full date, or empty)
        const formattedDate = parsePublishedDate(publishedDate);
        if (publishedDate && !formattedDate) {
            errors.push({ error: 'Invalid published date format.', book });
            continue;
        }

        try {
            // Check if the book with the same industryIdentifier already exists
            const existingBook = await BookBuy.findOne({ industryIdentifier: { $in: [industryIdentifier.trim()] } });

            if (existingBook) {
                // Log that the book is skipped due to duplicate industryIdentifier
                console.log(`Skipping duplicate book with industryIdentifier: ${industryIdentifier}`);
                errors.push({ error: 'Duplicate industryIdentifier found. Skipping book.', book });
                continue; // Skip the current book
            }

            // Prepare copies array if provided
            const copiesArray = copies
                ? copies.split(';').map(copy => {
                    const details = copy.split(',');
                    if (details.length !== 4) {
                        errors.push({ error: 'Invalid copies format.', book });
                        return null; // Skip this copy
                    }
                    return {
                        copyId: details[0],
                        bookLocation: details[1],
                        locationId: details[2],
                        availability: details[3] === 'true',
                    };
                }).filter(copy => copy !== null) // Remove null entries
                : []; // Default to an empty array if copies is not provided

            // Create a new purchase record using the book details
            const newBook = new BookBuy({
                userId,
                googleId, // Informational field, not used for duplicate checks
                industryIdentifier: industryIdentifier ? [industryIdentifier.trim()] : [],
                title,
                authors: authors ? authors.split(',') : ['Unknown Author'],
                publisher,
                publishedDate: formattedDate,
                description,
                pageCount: pageCount ? Number(pageCount) : undefined,
                categories: categories ? categories.split(',') : [],
                language,
                coverImage,
                purchaseDate: new Date(),
                copies: copiesArray // Optional field
            });

            // Save the new book to the database
            console.log('Attempting to save new book:', newBook);
            await newBook.save();
            console.log('Saved new book:', newBook.industryIdentifier);
        } catch (error) {
            console.error('Error processing book:', error.message);
            errors.push({ error: 'Failed to process book.', book, details: error.message });
        }
    }
}
/**
 * Helper function to parse flexible date formats for publishedDate.
 * - Accepts full dates (e.g., "2025-02-17", "02/17/2025").
 * - Accepts year-only (e.g., "2025").
 * - Returns null if invalid.
 */
function parsePublishedDate(dateString) {
    if (!dateString) return null; // Allow empty dates
    const fullDate = new Date(dateString);
    if (!isNaN(fullDate.getTime())) return fullDate; // Valid full date

    // Handle year-only format (e.g., "2025")
    if (/^\d{4}$/.test(dateString)) {
        return new Date(`${dateString}-01-01`); // Default to January 1st
    }

    // Invalid date format
    return null;
}
// API endpoint to export all purchases to CSV
app.get('/api/exportBooks', async(req, res) => {
    try {
        // Fetch all purchases from the database
        const purchases = await BookBuy.find();

        // Check if any purchases exist
        if (!purchases.length) {
            return res.status(404).json({ message: 'No purchases found.' });
        }

        // Prepare data for CSV
        const csvData = purchases.flatMap(purchase =>
            purchase.copies.map(copy => ({
                userId: purchase.userId,
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
                copyId: copy.copyId || 'N/A'
            }))
        );

        // Use json2csv to convert to CSV
        const json2csvParser = new Parser();
        const csv = json2csvParser.parse(csvData);

        // Create a blob and send the CSV file
        res.header('Content-Type', 'text/csv');
        res.attachment('purchases.csv');
        res.send(csv);
    } catch (error) {
        console.error('Error exporting books:', error);
        return res.status(500).json({ error: 'Error exporting books' });
    }
});

// API endpoint to get all purchases
app.get('/api/allPurchases', async(req, res) => {
    try {
        const purchases = await BookBuy.find();

        if (!purchases.length) {
            return res.status(404).json({ message: 'No purchases found.' });
        }

        return res.status(200).json(purchases);
        console.log('Fetched purchases:', purchases); // Log the fetched data
    } catch (error) {
        console.error('Error fetching all purchases:', error);
        return res.status(500).json({ error: 'Error fetching all purchases' });
    }
});

// API endpoint to delete a purchase by ObjectId
app.delete('/api/deletePurchase/:id', async(req, res) => {
    const { id } = req.params;

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ error: 'Invalid ObjectId format.' });
    }

    try {
        const result = await BookBuy.deleteOne({ _id: id });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Purchase not found.' });
        }

        return res.status(200).json({ message: 'Purchase deleted successfully.' });
    } catch (error) {
        console.error('Error deleting purchase:', error);
        return res.status(500).json({ error: 'Failed to delete purchase.' });
    }
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



// Endpoint to get all user borrow data without token validation
app.get('/api/show_userBorrows',authenticateToken, async (req, res) => {
    try {
        // Fetch all borrowed books data
        const allUserBorrowData = await UserBorrow.find({})
            .populate('userid', 'username') // Populate the 'userid' field with 'username'
            .exec();

        res.status(200).json(allUserBorrowData); // Return the data
    } catch (error) {
        console.error('Error fetching user borrow data:', error);
        res.status(500).json({ error: 'Failed to fetch user borrow data.' });
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