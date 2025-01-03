const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

const Book = require('./models/bookSchema'); // Import Book model
const User = require('./models/userSchema'); // Import User model

const app = express();
const PORT = 9875;
const SECRET_KEY = 'your_secure_secret_key';

// Middleware
app.use(cors({
    origin: 'http://localhost:3000', // Adjust this if your frontend runs on a different port
    credentials: true // Allow credentials for cookie/session management
}));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Express session setup
app.use(session({
    secret: 'your_session_secret', // Change this to a secure secret
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
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
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

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
    const user = await User.findOne({ username });

    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user._id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        const redirectUrl = user.role === 'admin' ? '/admin.html' :
                            user.role === 'librarian' ? '/librarian.html' : '/user.html';
        return res.json({ token, redirect: redirectUrl });
    } else {
        res.status(401).send('Invalid credentials');
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
        const existingUser = await User.findOne({ googleId: profile.id });
        if (existingUser) {
            return done(null, existingUser);
        }
        const newUser = new User({
            username: profile.displayName,
            googleId: profile.id,
            role: 'user' // Assign a default role
        });
        await newUser.save(); // Save the new user to MongoDB
        done(null, newUser);
    } catch (error) {
        done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

// Google auth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        // Successful authentication, redirect to index.html
        res.redirect('/'); // Redirect to the root URL where index.html is served
    });

app.get('/success', (req, res) => {
    res.send(`Welcome ${req.user.username}`); // Display welcome message or redirect to a frontend page
});

// User Management (admin only)
app.get('/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const users = await User.find();
    res.json(users);
});

app.post('/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, role });
    await newUser.save();
    res.json(newUser);
});

app.put('/users/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    await User.findByIdAndUpdate(req.params.id, req.body);
    res.status(204).send();
});

app.delete('/users/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    await User.findByIdAndDelete(req.params.id);
    res.status(204).send();
});

// API endpoint to search for books
app.get('/api/books', async (req, res) => {
    const search = req.query.q;

    try {
        const response = await axios.get(`https://www.googleapis.com/books/v1/volumes?q=${search}&key=AIzaSyCBY9btOSE4oWKYDJp_u5KrRI7rHocFB8A&maxResults=40`);
        const books = response.data.items;

        // Clear previous book data in the database
        await Book.deleteMany({});

        // Save books to MongoDB
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
        res.status(500).send('Error fetching data');
    }
});

// API endpoint to get book details by googleId
app.get('/api/books/:googleId', async (req, res) => {
    const { googleId } = req.params;

    try {
        const book = await Book.findOne({ googleId });

        if (!book) {
            return res.status(404).send('Book not found');
        }

        res.json(book);
    } catch (error) {
        console.error('Error fetching book details:', error);
        res.status(500).send('Error fetching book details');
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
        res.status(500).send('Server error');
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

// Start server and create default admin
app.listen(PORT, async () => {
    console.log(`Server running on http://localhost:${PORT}`);
    await createDefaultAdmin(); // Create default admin at startup
});

// Catch-all route to redirect to index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
