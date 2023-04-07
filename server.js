"use strict";
import { config } from 'dotenv';
import express from 'express';
import fs from 'fs';
import { passwordStrength } from 'check-password-strength';
import bcrypt from 'bcrypt'; 
import flash from 'express-flash';
import session from 'express-session';
import passport from 'passport';
import initializePassport from './passport-config.js';
import methodOverride from 'method-override';


/* DEFINITIONS */
let users = [];

// Create the user data from the text file and populate the users array
const loadUsers = () => {
    try {
      const data = fs.readFileSync('users.txt', 'utf8');
      users = JSON.parse(data);
      users.forEach((user) => {
        user.notes = user.notes || [];
      });
    } catch (err) {
      if (err.code === 'ENOENT') {
        fs.writeFileSync('users.txt', '[]');
      } else {
        console.error(err);
      }
    }
};

// Prevent non-user to access to the homepage
const checkAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    
    res.redirect('/login');
};

// Prevent user to go back to login page
const checkNotAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    next();
}



/* INITIALIZING AND LOADING MIDDLEWARES */
loadUsers();
config();
const app = express();
initializePassport(
    passport,
    name => users.find(user => user.name === name),
    id => users.find(user => user.id === id)
);
app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false 
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));




/* MAIN APPLICATION */
app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name, notes: req.user.notes });
});

// Add new note
app.post('/new-note', checkAuthenticated, (req, res) => {
    const user =  req.user;
    const id = Date.now().toString(); 
    const { title, content } = req.body;
    const newNote = { id, title, content };
    user.notes.push(newNote);
    fs.writeFileSync('users.txt', JSON.stringify(users));
    res.redirect('/');
})

// Delete an old note
app.delete('/delete-note/:noteId', checkAuthenticated, (req, res) => {
    const user = req.user;
    const noteId = req.params.noteId;
    user.notes = user.notes.filter((note) => note.id !== noteId);
    fs.writeFileSync('users.txt', JSON.stringify(users));
    res.redirect('/');
})




/* LOG IN TO ACCOUNT */
app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
});

app.post('/login', passport.authenticate('local', {
   successRedirect: '/',
   failureRedirect: '/login',
   failureFlash: true 
}));




/* REGISTER NEW ACCOUNT */
app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs', { message: null });
});

app.post('/register', async (req, res) => {
    const { username, new_password, confirm } = req.body;

    // Check password strength
    const passwordStrengthResult = passwordStrength(new_password);
    if (passwordStrengthResult.value !== "Strong") {
        return res.render('register.ejs', 
            { message: 'Your password is not strong enough'}
        );
    }

    // Check password retype
    if (new_password !== confirm) {
        return res.render('register.ejs', 
            { message: "Password does not match." }
        );
    }

    // Hash password and store in the text file
    try {
        const hashedPassword = await bcrypt.hash(req.body.new_password, 10);
        users.push({
            id: Date.now().toString(),
            name: req.body.username,
            password: hashedPassword,
            notes: []
        });
        fs.writeFileSync('users.txt', JSON.stringify(users));
        res.redirect('/login');
    } catch {
        res.redirect('/register');
    }
});



/* LOG OUT */
app.delete('/logout', (req, res) => {
    req.logOut((err) => {
        if (err) { return next(err); }
        res.redirect('/login');
    });
})




app.listen(3000);

