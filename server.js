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
require('dotenv').config();

const Book = require('./models/bookSchema');
const User = require('./models/userSchema');
const UserBorrow = require('./models/bookBorrowSchema');
const Comment = require('./models/commentSchema');
const AdminBook = require('./models/adminBookSchema');
const BookBuy = require('./models/buyBookSchema');

const app = express();
const PORT = process.env.PORT || 9875
const SECRET_KEY = 'your_secure_secret_key';

// Middleware
app.use(cors({
    origin: 'http://localhost:3000',
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

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

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



// Excel import route for users
app.post('/import-excel-users', upload.single('file'), async(req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

    const usersToCreate = data.map(async(user) => {
        if (!user.username || !user.password) {
            throw new Error('Username and password are required.');
        }

        const hashedPassword = await bcrypt.hash(user.password, 10);
        return {
            username: user.username,
            password: hashedPassword,
            role: user.role || 'user' // Default role if not provided
        };
    });

    try {
        const users = await User.insertMany(await Promise.all(usersToCreate));
        res.status(201).json(users);
    } catch (error) {
        res.status(500).send('Error importing users: ' + error.message);
    }
});

// Excel import route for books
app.post('/import-excel-books', upload.single('file'), async(req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

    const booksToCreate = data.map((book) => {
        if (!book.title || !book.author || !book.year || !book.isbn) {
            throw new Error('Title, author, year, and ISBN are required.');
        }

        return {
            title: book.title,
            author: book.author,
            year: book.year,
            isbn: book.isbn
        };
    });

    try {
        const books = await Book.insertMany(booksToCreate);
        res.status(201).json(books);
    } catch (error) {
        res.status(500).send('Error importing books: ' + error.message);
    }
});
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


// API endpoint to borrow a book
app.post('/api/userBorrows', authenticateToken, async(req, res) => {
    const { googleId, userid } = req.body;

    // Validate request body
    if (!googleId || !userid) {
        return res.status(400).json({ error: 'Missing googleId or userid.' });
    }

    // Ensure userid matches the authenticated user
    if (userid !== req.user.id) {
        return res.status(403).json({ error: 'You do not have permission to borrow this book.' });
    }

    try {
        // Check if the user has already borrowed this book
        const existingBorrow = await UserBorrow.findOne({ googleId, userid });

        if (existingBorrow) {
            if (!existingBorrow.returned) {
                return res.status(400).json({ error: 'You have already borrowed this book and it is not returned.' });
            } else {
                // If it has been returned, allow borrowing again
                // Consider updating the existing record instead of creating a new one
                existingBorrow.returned = false; // Update the returned status
                existingBorrow.borrowDate = new Date(); // Update the borrow date
                existingBorrow.dueDate = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000); // Update due date
                await existingBorrow.save(); // Save the updated borrow record
                return res.status(200).json({
                    message: 'Book borrowed successfully',
                    borrowInfo: existingBorrow
                });
            }
        }

        // Proceed with borrowing the book if no existing record
        const userBorrow = new UserBorrow({
            userid: userid,
            googleId: googleId,
            returned: false, // Set to false when borrowing
            borrowDate: new Date(), // Set to the current date
            dueDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // Set due date to 14 days from now
        });

        const savedBorrow = await userBorrow.save();
        return res.status(201).json({
            message: 'Book borrowed successfully',
            borrowInfo: savedBorrow
        });
    } catch (error) {
        console.error('Error borrowing book:', error);
        return res.status(500).json({ error: 'Error borrowing book' });
    }
});


// API endpoint to check borrowing status
app.get('/api/userBorrows/check', authenticateToken, async(req, res) => {
    const { googleId, userid } = req.query;

    if (!googleId || !userid || userid !== req.user.id) {
        return res.status(400).json({ error: 'Invalid request.' });
    }

    try {
        const existingBorrow = await UserBorrow.findOne({ googleId, userid });
        if (existingBorrow) {
            return res.status(200).json({ borrowed: true, returned: existingBorrow.returned });
        }

        return res.status(200).json({ borrowed: false });
    } catch (error) {
        console.error('Error checking borrow status:', error);
        return res.status(500).json({ error: 'Error checking borrow status' });
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



app.post('/api/admin_books/', authenticateToken, async(req, res) => {
    const { googleId, bookLocation, locationId, availability, noOfCopy } = req.body;

    // Input validation
    if (!googleId || !bookLocation || !locationId || isNaN(noOfCopy) || noOfCopy < 1) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const book = await Book.findOne({ googleId });
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        const adminBooks = [];
        for (let i = 0; i < noOfCopy; i++) {
            const newAdminBook = new AdminBook({
                googleId,
                bookLocation,
                locationId,
                availability,
                noOfCopy: 1
            });
            const savedAdminBook = await newAdminBook.save();
            adminBooks.push({
                copyId: savedAdminBook._id,
                adminBook: savedAdminBook
            });
        }

        res.status(201).json({
            adminBooks: adminBooks.map(book => ({
                googleId: book.adminBook.googleId,
                copyId: book.copyId,
                bookLocation: book.adminBook.bookLocation,
                locationId: book.adminBook.locationId,
                availability: book.adminBook.availability,
                noOfCopy: book.adminBook.noOfCopy,
            }))
        });
    } catch (error) {
        console.error('Error adding admin book:', error);
        res.status(500).json({ error: 'Failed to add admin book.', details: error.message });
    }
});

// API endpoint to get all admin books
app.get('/api/admin_books', authenticateToken, async(req, res) => {
    try {
        const adminBooks = await AdminBook.find();
        res.status(200).json(adminBooks.map(book => ({
            googleId: book.googleId,
            copyId: book._id, // Use the ObjectId as copyId
            bookLocation: book.bookLocation,
            locationId: book.locationId,
            availability: book.availability,
            noOfCopy: book.noOfCopy,
        })));
    } catch (error) {
        console.error('Error retrieving admin books:', error);
        res.status(500).json({ error: 'Failed to retrieve admin books.' });
    }
});
app.put('/api/admin_books/:copyId', authenticateToken, async(req, res) => {
    const copyId = req.params.copyId.trim().replace(/\s+/g, ''); // Clean copyId
    console.log('Received copyId:', copyId);
    console.log('Length of copyId:', copyId.length); // Check length
    console.log('Type of copyId:', typeof copyId); // Check type

    // Convert copyId to mongoose ObjectId
    let objectId;
    try {
        objectId = new mongoose.Types.ObjectId(copyId);
        console.log('Converted to ObjectId:', objectId); // Log converted ObjectId
    } catch (error) {
        console.error('Error converting copyId to ObjectId:', error.message);
        return res.status(400).json({ error: 'Invalid copyId format' });
    }

    const { bookLocation, locationId, availability, noOfCopy } = req.body;

    // Input validation
    if (!bookLocation || !locationId || noOfCopy < 1) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const updatedAdminBook = await AdminBook.findOneAndUpdate({ _id: objectId }, { bookLocation, locationId, availability, noOfCopy }, { new: true });

        if (!updatedAdminBook) {
            return res.status(404).json({ error: 'Admin book not found' });
        }

        res.json(updatedAdminBook);
    } catch (error) {
        console.error('Error updating admin book:', error.message);
        res.status(500).json({ error: 'Failed to update admin book' });
    }
});

// API endpoint to delete an admin book
app.delete('/api/admin_books/:copyId', authenticateToken, async(req, res) => {
    const copyId = req.params.copyId.trim().replace(/\s+/g, ''); // Clean copyId
    console.log('Received copyId:', copyId);

    // Convert copyId to mongoose ObjectId
    let objectId;
    try {
        objectId = new mongoose.Types.ObjectId(copyId);
    } catch (error) {
        console.error('Error converting copyId to ObjectId:', error.message);
        return res.status(400).json({ error: 'Invalid copyId format' });
    }

    try {
        const deletedBook = await AdminBook.findOneAndDelete({ _id: objectId });
        if (!deletedBook) {
            return res.status(404).json({ error: 'Book not found' });
        }
        res.sendStatus(204); // No Content
    } catch (error) {
        console.error('Error deleting admin book:', error.message);
        res.status(500).json({ error: 'Failed to delete admin book.' });
    }
});

// Middleware to check if the user is an admin
const checkAdminRole = (req, res, next) => {
    // Log the user role to the console
    console.log(`User role: ${req.user.role}`);

    if (req.user.role !== 'admin') {
        return res.sendStatus(403); // Forbidden
    }
    next();
};

// Route to serve the book administration page
app.get('/book_admin.html', authenticateToken, checkAdminRole, (req, res) => {
    // If the user is an admin, send the book administration page
    res.sendFile(path.join(__dirname, 'public', 'book_admin.html'));
});

app.get('/api/user-role', async(req, res) => {
    try {
        // Extract token from headers
        const authHeader = req.headers['authorization']; // Get the Authorization header
        const token = authHeader && authHeader.split(' ')[1]
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
app.delete('/api/userPurchases', authenticateToken, async(req, res) => {
    const { googleId, userid } = req.query;

    // Validate request parameters
    if (!googleId || !userid) {
        return res.status(400).json({ error: 'Missing googleId or userid.' });
    }

    // Ensure userid matches the authenticated user
    if (userid !== req.user.id) {
        console.log(`Permission denied. User ID: ${userid}, Authenticated User ID: ${req.user.id}`);
        return res.status(403).json({ error: 'You do not have permission to delete this purchase.' });
    }

    try {
        const result = await BookBuy.deleteOne({ googleId: googleId, userid: userid });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Purchase not found.' });
        }

        res.json({ message: 'Purchase deleted successfully.' });
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
            // Check if industryIdentifier exists and is not empty
            if (!purchase.industryIdentifier || purchase.industryIdentifier.length === 0) {
                return {
                    ...purchase.toObject(),
                    googleBookDetails: null, // Set googleBookDetails to null if identifier is missing
                };
            }

            const isbn = purchase.industryIdentifier[0]; // Get the first identifier
            const isbnResponse = await fetch(`https://www.googleapis.com/books/v1/volumes?q=isbn:${isbn}`);
            const isbnData = await isbnResponse.json();

            // Check if the response is okay and contains valid items
            if (isbnResponse.ok && isbnData.totalItems > 0) {
                return {
                    ...purchase.toObject(),
                    googleBookDetails: isbnData.items[0], // Use the first item
                };
            } else {
                console.warn(`ISBN not found for ${isbn}. Attempting to fetch by googleId: ${purchase.googleId}`);

                // Fallback to fetch by googleId
                const googleIdResponse = await fetch(`https://www.googleapis.com/books/v1/volumes/${purchase.googleId}`);
                const googleIdData = await googleIdResponse.json();

                if (googleIdResponse.ok) {
                    return {
                        ...purchase.toObject(),
                        googleBookDetails: googleIdData, // Use the data from googleId
                    };
                } else {
                    console.error(`Failed to fetch details for googleId: ${purchase.googleId}`);
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
app.post('/api/importBooks', async(req, res) => {
    const { books } = req.body;

    if (!Array.isArray(books) || books.length === 0) {
        return res.status(400).json({ error: 'Invalid book data provided.' });
    }

    try {
        // Set a default user ID for testing
        const userId = 'defaultUserId'; // Replace with a valid user ID if needed

        // Prepare to hold the results of the insertion process
        const savedPurchases = [];
        const errors = [];

        for (const book of books) {
            const { googleId } = book;

            // Validate required fields
            if (!googleId) {
                errors.push({ error: 'Missing googleId for a book.', book });
                continue; // Skip this book and move to the next one
            }

            // Create a new purchase record using the book details
            const purchase = new BookBuy({
                userid: userId,
                googleId: googleId,
                industryIdentifier: book.industryIdentifier || [], // Use empty array if not provided
                title: book.title || 'Unknown Title', // Default title if not provided
                subtitle: book.subtitle || 'No Subtitle', // Default subtitle if not provided
                authors: book.authors || 'Unknown Author', // Default authors if not provided
                publisher: book.publisher || 'Unknown Publisher', // Default publisher if not provided
                publishedDate: book.publishedDate || 'Unknown Date', // Default date if not provided
                description: book.description || 'No Description', // Default description if not provided
                pageCount: book.pageCount || 0, // Default page count if not provided
                categories: book.categories || [], // Use empty array if not provided
                language: book.language || 'en', // Default language if not provided
                coverImage: book.coverImage || '', // Default empty string if not provided
                purchaseDate: new Date() // Automatically set the purchase date
            });

            // Save the purchase to the database
            const savedPurchase = await purchase.save();
            savedPurchases.push(savedPurchase);
        }

        // Send response with success and error messages
        res.status(201).json({
            message: 'Books imported successfully!',
            savedPurchases: savedPurchases,
            errors: errors.length > 0 ? errors : undefined
        });
    } catch (error) {
        console.error('Error importing books:', error);
        res.status(500).json({ error: 'Failed to import books.' });
    }
});
// API endpoint to get all purchases
app.get('/api/allPurchases', async(req, res) => {
    try {
        // Find all purchases
        const purchases = await BookBuy.find();

        if (!purchases.length) {
            return res.status(404).json({ message: 'No purchases found.' });
        }

        return res.status(200).json(purchases);
    } catch (error) {
        console.error('Error fetching all purchases:', error);
        return res.status(500).json({ error: 'Error fetching all purchases' });
    }
});
// API endpoint to delete a purchase by googleId
app.delete('/api/deletePurchase', async(req, res) => {
    const { googleId } = req.query;

    if (!googleId) {
        return res.status(400).json({ error: 'Missing googleId.' });
    }

    try {
        const result = await BookBuy.deleteOne({ googleId });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Purchase not found.' });
        }

        return res.status(200).json({ message: 'Purchase deleted successfully.' });
    } catch (error) {
        console.error('Error deleting purchase:', error);
        return res.status(500).json({ error: 'Failed to delete purchase.' });
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