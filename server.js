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

const Book = require('./models/bookSchema');
const User = require('./models/userSchema');
const UserBorrow = require('./models/bookBorrowSchema');
const Comment = require('./models/commentSchema');
const AdminBook = require('./models/adminBookSchema');

const app = express();
const PORT = 9875;
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

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401); // No token

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden
        req.user = user; // Attach user info to the request
        next();
    });
};
//API endpoint to get borrow history for a specific user
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

// API endpoint to borrow a book
// API endpoint to borrow a book
app.post('/api/userBorrows', authenticateToken, async (req, res) => {
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
app.get('/api/userBorrows/check', authenticateToken, async (req, res) => {
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
// API endpoint to update borrow status (return a book)
app.put('/api/userBorrows/:id', authenticateToken, async (req, res) => {
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
const createDefaultAdmin = async () => {
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
        const user = await User.findOne({ username });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

        console.log(`User logged in: ${user.username}`);
        return res.json({ token, redirect: `http://localhost:9875/index.html?userid=${user._id}` });
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// User Signup
app.post('/users', async (req, res) => {
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
}, async (request, accessToken, refreshToken, profile, done) => {
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

passport.deserializeUser(async (id, done) => {
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
        res.redirect(`http://localhost:9875/index.html?userid=${req.user._id}`);
    }
);

// User Management (admin only)
app.get('/users', authenticateToken, async (req, res) => {
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
app.get('/api/users', async (req, res) => {
    try {
        // Extract userId from query parameters
        const userId = req.query.userid;

        // Extract token from headers
        const token = req.headers['authorization']?.split(' ')[1];
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
app.put('/users/:id', authenticateToken, async (req, res) => {
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
app.delete('/users/:id', authenticateToken, async (req, res) => {
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
app.get('/api/books', async (req, res) => {
    const search = req.query.q;

    try {
        const response = await axios.get(`https://www.googleapis.com/books/v1/volumes?q=${search}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A&maxResults=40`); // Replace with your actual API key
        const books = response.data.items;

        await Book.deleteMany({}); 

        for (const book of books) {
            const industryIdentifier = book.volumeInfo.industryIdentifiers ? book.volumeInfo.industryIdentifiers[0].identifier : 'N/A';
            const newBook = new Book({
                googleId: book.id,
                industryIdentifier: industryIdentifier,
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

        res.json({ data: books });
    } catch (error) {
        console.error('Error fetching data from Google Books API:', error);
        res.status(500).json({ error: 'Error fetching data' });
    }
});

// API endpoint to get book details by googleId
app.get('/api/books/:googleId', async (req, res) => {
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
app.get('/books', authenticateToken, async (req, res) => {
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

app.post('/books', authenticateToken, async (req, res) => {
    if (req.user.role !== 'librarian') return res.sendStatus(403);
    const newBook = new Book(req.body);
    await newBook.save();
    res.json(newBook);
});

app.put('/books/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'librarian') return res.sendStatus(403);
    await Book.findByIdAndUpdate(req.params.id, req.body);
    res.status(204).send();
});

app.delete('/books/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'librarian') return res.sendStatus(403);
    await Book.findByIdAndDelete(req.params.id);
    res.status(204).send();
});
// API endpoint to create a comment
app.post('/api/comments', authenticateToken, async (req, res) => {
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
app.put('/api/comments/:id', authenticateToken, async (req, res) => {
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

// API endpoint to add new admin books
app.post('/api/admin_books', authenticateToken, async (req, res) => {
    const { googleId, bookLocation, locationId, availability, noOfCopy } = req.body;

    try {
        const book = await Book.findOne({ googleId });
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        // Create a new AdminBook instance without copyId first
        const newAdminBook = new AdminBook({
            googleId,
            bookLocation,
            locationId,
            availability,
            noOfCopy,
        });

        // Save the new AdminBook to the database
        const savedAdminBook = await newAdminBook.save();

        // Set the copyId to the ObjectId of the newly created AdminBook
        const copyId = savedAdminBook._id;

        // Return the copyId along with the new admin book details
        res.status(201).json({ 
            copyId: copyId, // Provide the ObjectId as copyId
            adminBook: savedAdminBook,
            book 
        });
    } catch (error) {
        console.error('Error adding admin book:', error);
        res.status(500).json({ error: 'Failed to add admin book.' });
    }
});

// API endpoint to get all admin books
app.get('/api/admin_books', authenticateToken, async (req, res) => {
    try {
        const adminBooks = await AdminBook.find();
        res.status(200).json(adminBooks.map(book => ({
            googleId: book.googleId,
            copyId: book._id, // Use the ObjectId as copyId
            bookLocation: book.bookLocation,
            locationId: book.locationId,
            availability: book.availability,
            noOfCopy: book.noOfCopy,
        }))); // Return all admin books with necessary fields
    } catch (error) {
        console.error('Error retrieving admin books:', error);
        res.status(500).json({ error: 'Failed to retrieve admin books.' });
    }
});

// API endpoint to update an admin book
app.put('/api/admin_books/:copyId', authenticateToken, async (req, res) => {
    const { copyId } = req.params;
    const { bookLocation, locationId, availability, noOfCopy } = req.body;

    try {
        const updatedAdminBook = await AdminBook.findByIdAndUpdate(
            copyId,
            { bookLocation, locationId, availability, noOfCopy },
            { new: true } // Return the updated document
        );

        if (!updatedAdminBook) {
            return res.status(404).json({ error: 'Admin book not found' });
        }

        res.json(updatedAdminBook); // Send back the updated admin book
    } catch (error) {
        console.error('Error updating admin book:', error);
        res.status(500).json({ error: 'Failed to update admin book' });
    }
});

// API endpoint to delete an admin book
app.delete('/api/admin_books/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        const deletedBook = await AdminBook.findByIdAndDelete(id);
        if (!deletedBook) {
            return res.status(404).json({ error: 'Book not found' });
        }
        res.sendStatus(204); // No Content
    } catch (error) {
        console.error('Error deleting admin book:', error);
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

app.get('/api/user-role', async (req, res) => {
    try {
        // Extract token from headers
        const token = req.headers['authorization']?.split(' ')[1];
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
// Start server and create default admin
app.listen(PORT, async () => {
    console.log(`Server running on http://localhost:${PORT}`);
    await createDefaultAdmin();
});


// Catch-all route to redirect to index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
