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
const PORT = process.env.PORT || 9875
const SECRET_KEY = 'your_secure_secret_key';

// Middleware
app.use(cors({
    origin: 'http://localhost:9875',
    credentials: true
}));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Express session setup
app.use(session({
    secret: 'your_session_secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
}));

app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
const mongoURI = "mongodb+srv://Admin:admin@library.8bgvj.mongodb.net/bookManagement?retryWrites=true&w=majority&appName=Library";
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

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
// Set the refresh token
oauth2Client.setCredentials({
    refresh_token: '1//04t2NpS9k9vy_CgYIARAAGAQSNwF-L9Ir5SWysiyTCHoK6ZKYzFdnBI4Onm4-hpR0y_MdtNIZEVZePQE-sHPZpRbsUoT4ld7_hMk' // Replace with your Refresh Token
});
app.post('/send-email', async (req, res) => {
    try {
        // Fetch user details from the database (you can modify the query as needed)
        const userDetails = await UserDetails.findOne(); // Fetch the first user for demonstration

        if (!userDetails) {
            return res.status(404).send('No user found.');
        }

        const fromAddress = 'abbichiu@gmail.com'; // Sender email
        const toAddress = userDetails.email;       // Recipient email from the user details

        if (!toAddress) {
            return res.status(400).send('Recipient address is required.');
        }

        // Compose the email including the current loans
        let loanDetailsText = 'Current Loans:\n\n';
        
        userDetails.currentLoans.forEach((loan, index) => {
            loanDetailsText += `Loan ${index + 1}:\n`;
            loanDetailsText += `Title: ${loan.details.title}\n`;
            loanDetailsText += `Authors: ${loan.details.authors.join(', ')}\n`;
            loanDetailsText += `Borrow Date: ${loan.details.borrowDate}\n`;
            loanDetailsText += `Due Date: ${loan.details.dueDate}\n`;
            loanDetailsText += `Returned: ${loan.details.returned ? 'Yes' : 'No'}\n`;
            loanDetailsText += `Comments: ${loan.details.comments.join(', ')}\n\n`;
        });

        const email = `From: ${fromAddress}
To: ${toAddress}
Subject: Your Current Loan Details

Hello ${userDetails.name},

Here are your current loan details:

${loanDetailsText}

Best regards,
Library Team`;

        console.log('Email:', email);

        // Encode the email in Base64 URL format
        const encodedEmail = base64url.encode(email);
  
        // Prepare the request body
        const requestBody = {
            raw: encodedEmail,
        };
        console.log('Request Body:', requestBody);

        // Get access token
        const accessToken = await getAccessToken(); // Ensure this function gets your access token
        console.log('Access Token:', accessToken);

        // Send the email using the Gmail API
        const response = await axios.post('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', requestBody, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
        });

        res.status(200).send(`Email sent successfully! Message ID: ${response.data.id}`);
    } catch (error) {
        console.error('Error details:', error.response ? error.response.data : error.message);
        res.status(500).send('Error sending email');
    }
});

  app.get('/get-email/:id', async (req, res) => {
    const messageId = req.params.id;

    try {
        const accessToken = await oauth2Client.getAccessToken();
        
        const response = await axios.get(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}`, {
            headers: {
                Authorization: `Bearer ${accessToken.token}`,
                'Content-Type': 'application/json',
            },
        });

        res.status(200).json(response.data);
    } catch (error) {
        console.error('Error fetching email details:', error.response ? error.response.data : error.message);
        res.status(500).send('Error fetching email details');
    }
});
// Function to get a new access token
async function getAccessToken() {
    try {
        const { token } = await oauth2Client.getAccessToken();
        return token;
    } catch (error) {
        console.error('Error refreshing access token:', error);
        throw error;
    }
}

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

//API endpoint to get borrow history for a specific user
app.get('/api/userBorrows', authenticateToken, async(req, res) => {
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

// API endpoint to borrow a book
app.post('/api/userBorrows', authenticateToken, async (req, res) => {
    const { userid, isbn } = req.body;

    // Validate request body
    if (!userid) {
        return res.status(400).json({ error: 'Missing userid.' });
    }

    // Ensure userid matches the authenticated user
    if (userid !== req.user.id) {
        return res.status(403).json({ error: 'You do not have permission to borrow this book.' });
    }

    try {
        // Check if the user has borrowed this book using isbn
        let existingBorrow = await UserBorrow.findOne({
            userid,
            returned: false,
            industryIdentifier: { $in: [isbn] } // Check if isbn is in the industryIdentifier array
        });
        // If a record exists and it's not returned, prevent borrowing again
        if (existingBorrow) {
            return res.status(400).json({ error: 'You have already borrowed this book.' });
        }

        // If no existing record, check if the book was previously borrowed and returned
        existingBorrow = await UserBorrow.findOne({
            userid,
            industryIdentifier: { $in: [isbn] },
            returned: true
        });

         // If a returned record exists, allow borrowing again
         if (existingBorrow) {
            existingBorrow.returned = false; // Set to false when borrowing again
            existingBorrow.borrowDate = setMidnight(new Date());
            existingBorrow.dueDate = setMidnight(new Date(Date.now() + 14 * 24 * 60 * 60 * 1000));

            await existingBorrow.save();
            return res.status(200).json({
                message: 'Book borrowed successfully (previously returned)',
                borrowInfo: existingBorrow
            });
        }
        // No existing borrow records, proceed to borrow the book
        if (!isbn) {
            return res.status(400).json({ error: 'ISBN is required to borrow the book.' });
        }

        let book = await Book.findOne({ industryIdentifier: isbn });

        if (!book) {
            const response = await axios.get(`https://www.googleapis.com/books/v1/volumes?q=isbn:${isbn}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A`);
            const items = response.data.items;

            if (!items || items.length === 0) {
                return res.status(404).json({ error: 'Book not found by ISBN.' });
            }

            const googleBook = items[0];
            book = new Book({
                googleId: googleBook.id,
                industryIdentifier: isbn,
                title: googleBook.volumeInfo.title,
                // ... other fields
            });

            await book.save();
        }

        const userBorrow = new UserBorrow({
            userid: userid,
            googleId: null, // Remove googleId as it's not used
            title: book.title,
            authors: book.authors || [],
            publisher: book.publisher || 'N/A',
            publishedDate: book.publishedDate || 'N/A',
            industryIdentifier: [isbn],
            returned: false, // Set to false when borrowing
            borrowDate: setMidnight(new Date()),
            dueDate: setMidnight(new Date(Date.now() + 14 * 24 * 60 * 60 * 1000))
        });

        const savedBorrow = await userBorrow.save();
        return res.status(201).json({
            message: 'Book borrowed successfully',
            borrowInfo: savedBorrow
        });

    } catch (error) {
        console.error('Error borrowing book:', error.message, error.stack);
        return res.status(500).json({ error: error.message });
    }
});




// API endpoint to update borrow status (return a book)
app.put('/api/userBorrows/:id', authenticateToken, async(req, res) => {
    const { id } = req.params;
    const { returned } = req.body; // Accept returned status from request body

    try {
        // Validate the returned value
        if (typeof returned !== 'boolean') {
            return res.status(400).json({ error: 'Returned status must be a boolean' });
        }

        // Find the borrow record and update the returned status
        const updatedBorrow = await UserBorrow.findByIdAndUpdate(id, { returned: returned }, { new: true });

        if (!updatedBorrow) {
            return res.status(404).json({ error: 'Borrow record not found' });
        }

        res.json(updatedBorrow);
    } catch (error) {
        console.error('Error updating borrow status:', error);
        res.status(500).json({ error: 'Failed to update borrow status' });
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
app.post('/login', async(req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

        console.log(`User logged in: ${user.username}`);
        // Log the user's role
        console.log(`User logged in: ${user.username}, Role: ${user.role}`);


        const redirectUrl = user.role === 'admin' ? '/admin.html' :
            user.role === 'librarian' ? `http://localhost:9875/index_logined.html?userid=${user._id}` : `http://localhost:9875/index_userlogined.html?userid=${user._id}`;
        return res.json({ token, redirect: redirectUrl });
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// User Signup
app.post('/users', async(req, res) => {
    const { username, password, role = 'user' } = req.body;

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
    callbackURL: "http://localhost:9875/auth/google/callback",
    passReqToCallback: true
}, async(request, accessToken, refreshToken, profile, done) => {
    try {
        let existingUser = await User.findOne({ googleId: profile.id });
        if (existingUser) {
            return done(null, existingUser); // Pass the user directly
        }
        const newUser = new User({
            username: profile.displayName,
            googleId: profile.id,
            role: 'user'
        });
        await newUser.save();
        console.log(`User created via Google: ${newUser.username}`);
        return done(null, newUser);
    } catch (error) {
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user._id); // Serialize the user ID
});

passport.deserializeUser(async(id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// Google auth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        const token = jwt.sign({ id: req.user._id, role: req.user.role }, SECRET_KEY, { expiresIn: '1h' });
        // Redirect directly to index.html with the user ID as a query parameter
        res.redirect(`http://localhost:9875/index_logined.html?userid=${req.user._id}`);
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
app.get('/api/books/:googleId', async(req, res) => {
    const { googleId } = req.params;

    try {
        const book = await Book.findOne({ googleId });

        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        res.json(book);
    } catch (error) {
        console.error('Error fetching book details:', error);
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
app.post('/api/comments', authenticateToken, async(req, res) => {
    const { bookId, rating, comment } = req.body;

    if (!bookId || !rating || !comment) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    const newComment = new Comment({
        bookId,
        userId: req.user.id,
        rating,
        comment
    });

    try {
        const savedComment = await newComment.save();
        res.status(201).json(savedComment);
    } catch (error) {
        console.error('Error creating comment:', error);
        res.status(500).json({ error: 'Failed to create comment' });
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
app.post('/api/admin_books', authenticateToken, async(req, res) => {
    const { isbn, bookLocation, locationId, availability, noOfCopy } = req.body;

    // Input validation
    if (!isbn || !bookLocation || !locationId || isNaN(noOfCopy) || noOfCopy < 1) {
        return res.status(400).json({ error: 'Missing required fields' });
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
                noOfCopy: 1,
                title: bookInfo.title,
                authors: (bookInfo.authors && bookInfo.authors.length > 0) ? bookInfo.authors.join(', ') : 'Unknown',
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
                authors: bookInfo.authors || [],
                publisher: bookInfo.publisher,
                publishedDate: bookInfo.publishedDate,
                description: bookInfo.description,
                categories: bookInfo.categories || [],
                coverImage: bookInfo.imageLinks ? bookInfo.imageLinks.thumbnail : null,
                copies: copies, // Include copies array
            });
            await newBookBuy.save(); // Save the new book to the BookBuy collection
        }

        res.status(201).json({
            adminBooks: adminBooks.map(book => ({
                industryIdentifier: book.adminBook.industryIdentifier,
                copyId: book.copyId,
                bookLocation: book.adminBook.bookLocation,
                locationId: book.adminBook.locationId,
                availability: book.adminBook.availability,
                noOfCopy: book.adminBook.noOfCopy,
                title: book.adminBook.title,
                authors: book.adminBook.authors,
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
            industryIdentifier: book.industryIdentifier,
            googleId: book.googleId,

            bookLocation: book.bookLocation,
            locationId: book.locationId,
            availability: book.availability,
            noOfCopy: book.noOfCopy,
            title: book.title,
            author: book.author,
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



// API endpoint to import books from CSV
const upload = multer({ dest: 'uploads/' }); // Temporary file storage


// API endpoint to import books from CSV
app.post('/api/importBooks', upload.single('file'), async(req, res) => {
    const results = [];
    const errors = [];

    // Check if the request contains a file
    if (req.file) {
        // Read CSV file and parse it
        fs.createReadStream(req.file.path)
            .pipe(csv({ separator: ',' })) // Adjust for comma-separated values
            .on('data', (data) => {
                results.push(data);
            })
            .on('end', async() => {
                await processBooks(results, errors);
                fs.unlinkSync(req.file.path); // Clean up uploaded file
                sendResponse(res, errors);
            })
            .on('error', (error) => {
                console.error('Error parsing CSV:', error);
                return res.status(400).json({ error: 'Error parsing CSV file.' });
            });
    } else if (req.body.books) {
        // Handle JSON input
        await processBooks(req.body.books, errors);
        sendResponse(res, errors);
    } else {
        // No valid input provided
        return res.status(400).json({ error: 'No valid input provided. Please upload a file or provide JSON.' });
    }
});

async function processBooks(books, errors) {
    const userId = 'defaultUserId'; // Replace with a valid user ID if needed

    for (const book of books) {
        const {
            googleId,
            title,
            authors,
            publisher,
            publishedDate,
            description,
            pageCount,
            categories,
            language,
            coverImage,
            copies // This should be a string of copies
        } = book;

        // Validate required fields
        if (!title) {
            errors.push({ error: 'Missing title for a book.', book });
            continue;
        }

        // Validate publishedDate
        if (!isValidDate(publishedDate)) {
            errors.push({ error: 'Invalid published date for a book.', book });
            continue;
        }

        // Prepare copies array from CSV or JSON data
        const copiesArray = (copies || '').split(';').map(copy => {
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
        }).filter(copy => copy !== null); // Remove null entries

        // Create a new purchase record using the book details
        const purchase = new BookBuy({
            userId,
            googleId,
            industryIdentifier: book.industryIdentifier ? [book.industryIdentifier] : [],
            title,
            authors: authors ? authors.split(',') : ['Unknown Author'],
            publisher,
            publishedDate,
            description,
            pageCount: pageCount ? Number(pageCount) : undefined,
            categories: categories ? categories.split(',') : [],
            language,
            coverImage,
            purchaseDate: new Date(),
            copies: copiesArray
        });

        // Save the purchase to the database
        try {
            await purchase.save();
        } catch (saveError) {
            console.error('Error saving book:', saveError.message);
            errors.push({ error: 'Failed to save book.', book, details: saveError.message });
        }
    }
}

function isValidDate(dateString) {
    const date = new Date(dateString);
    return !isNaN(date.getTime()); // Check if date is valid
}

function sendResponse(res, errors) {
    res.status(201).json({
        message: 'Books imported successfully!',
        errors: errors.length > 0 ? errors : undefined
    });
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
app.post('/api/userDetails', authenticateToken, async (req, res) => {
    const { userId, name, email, phone, libraryCard } = req.body;

    if (!userId || !name || !email || !phone || !libraryCard) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        let userDetails = await UserDetails.findOne({ userId });

        if (userDetails) {
            // Update user details
            userDetails.name = name;
            userDetails.email = email;
            userDetails.phone = phone;
            userDetails.libraryCard = libraryCard;

            // Optionally, if you want to update currentLoans from UserBorrow
            const borrows = await UserBorrow.find({ userid: userId, returned: false });
            userDetails.currentLoans = borrows.map(borrow => ({
                borrowId: borrow._id,
                details: {
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
                    returned: borrow.returned
                }
            }));

            await userDetails.save();
            return res.status(200).json({ message: 'User details updated successfully.' });
        } else {
            // Create new user details
            userDetails = new UserDetails({
                userId,
                name,
                email,
                phone,
                libraryCard,
            });

            await userDetails.save();
            return res.status(201).json({ message: 'User details saved successfully.' });
        }
    } catch (error) {
        console.error('Error saving user details:', error.message);
        return res.status(500).json({ error: error.message });
    }
});

// Get userDetails
app.get('/api/userDetails', authenticateToken, async (req, res) => {
    const { userid } = req.query;

    if (!userid) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    try {
        const userDetails = await UserDetails.findOne({ userId: userid })
            .populate('currentLoans.borrowId'); // Populate details from UserBorrow

        if (!userDetails) {
            return res.status(404).json({ error: 'User details not found.' });
        }

        return res.status(200).json(userDetails);
    } catch (error) {
        console.error('Error fetching user details:', error.message);
        return res.status(500).json({ error: error.message });
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

// Function to send an email using the Gmail API
async function sendEmail(accessToken, userEmail, recipientEmail, subject, message) {

    // Construct the email in plain text format
    const email = [
        `From: abbichiu@gmail.com`, // Fixed sender email
        `To: ${recipientEmail}`,
        `Subject: ${subject}`,
        '',
        message,
    ].join('\n');


    // Encode the email in base64url format
    const base64EncodedEmail = Buffer.from(email).toString('base64url');

    // Configure the request to the Gmail API
    const requestConfig = {
        method: 'POST',
        url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
        headers: {
            Authorization: `Bearer ${accessToken}`, // Use the received access token
            'Content-Type': 'application/json',
        },
        data: {
            raw: base64EncodedEmail, // Email body in base64url format
        },
    };

    // Send the email using Axios
    try {
        const response = await axios(requestConfig);
        console.log(`Email sent: ${response.data}`);
    } catch (error) {
        console.error('Error sending email:', error.response ? error.response.data : error.message);
    }
}

// Function to send loan reminder emails
async function sendLoanReminders() {
    try {
        const users = await UserDetails.find(); // Fetch all user details

        for (const user of users) {
            if (user.currentLoans && user.currentLoans.length > 0) {
                const loanDetails = user.currentLoans.map(loan => {
                    return `Title: ${loan.details.title}, Due Date: ${loan.details.dueDate}`;
                }).join('\n');

                // Get a new access token (implement this according to your OAuth2 setup)
                const accessToken = await getAccessToken();

                // Send the email with loan details
                await sendEmail(
                    accessToken, // Access token
                    user.email, // Recipient's email
                    'Loan Reminder', // Email subject
                    `Dear ${user.name},\n\nYou have the following current loans:\n${loanDetails}\n\nPlease make sure to return them by the due date.\n\nThank you!`
                );
            }
        }
    } catch (error) {
        console.error('Error sending loan reminders:', error.message);
    }
}

// Endpoint to trigger sending reminders
app.get('/send-reminders', async (req, res) => {
    try {
        await sendLoanReminders();
        res.send('Loan reminders sent successfully!');
    } catch (error) {
        res.status(500).send('Error sending reminders: ' + error.message);
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