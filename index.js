import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import pg from "pg";
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";
import { v2 as cloudinary } from "cloudinary";
import multer from "multer";
import fs from "fs";

// Initialize env config in project
env.config();
const app = express();
const PORT = 3000;
const saltRounds = 10;

// Create a session for user login
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}));

// Initialize passport for the project
app.use(passport.initialize());
// Initialize session
app.use(passport.session());

// create new instance of db
const db = new pg.Client({
    connectionString: process.env.SUPABASE_CONNECTION_STRING,
    ssl: {
        rejectUnauthorized: false // Required for Supabase in many environments
    }
});
// connect project to database
db.connect();

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure multer storage to use Cloudinary
const upload = multer({ dest: "uploads/" });

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.get('/', async (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect("/homepage");
    } else {
        res.render('register.ejs', { duplicateUser: false });
    }
});

app.get('/homepage', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/');
    }

    try {
        const result = await db.query(
            "SELECT image_url FROM images ORDER BY created_at DESC"
        );

        const images = result.rows.map(row => row.image_url);

        res.render('homepage.ejs', { images });

    } catch (error) {
        console.error(error);
        res.status(500).send("Server Error");
    }
});

app.get('/register', (req, res) => {
    res.redirect('/');
});

app.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/homepage');
    } else {
        res.render('login.ejs', { userNotFound: false });
    }
});

app.get('/logout', (req, res, next) => {
    req.logout(err => {
        if (err) {
            return next(err);
        }
        res.redirect('/login');
    });
});

app.post('/upload', upload.single('image'), async (req, res) => {
    try {
        const result = await cloudinary.uploader.upload(req.file.path);

        await db.query(
            "INSERT INTO images (image_url) VALUES ($1)",
            [result.secure_url]
        );

        res.redirect('/homepage');

    } catch (error) {
        console.error(error);
        res.status(500).send("Upload failed");
    }
});

app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        // Hash password using bcrypt and store in database
        bcrypt.hash(password, saltRounds, async (err, hash) => {
            if (err) {
                throw new Error("Error hashing password!");
            } else {
                const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
                // Check if email already exist in database
                if (result.rows.length > 0) {
                    res.render("register", { error: "User already Exists.", duplicateUser: true });
                } else {
                    try {
                        const result = await db.query("INSERT INTO USERS (email, password) VALUES($1, $2) RETURNING *", [email, hash]);
                        const user = result.rows[0];
                        req.login(user, err => {
                            if (err) throw new Error(err);
                            // Session saved
                            // Action to do next
                            res.redirect("/homepage");
                        })
                    } catch (err) {
                        console.error(err);
                    }
                }
            }
        })
    } catch (err) {
        console.error(err);
    }
});

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return res.status(500).render('login.ejs', { userNotFound: true, error: err });
        }
        if (!user) {
            return res.render('login.ejs', { userNotFound: true, error: "Invalid credidentials" });
        }
        req.login(user, err => {
            if (err) {
                return res.status(500).render('login.ejs', { userNotFound: true, error: "Invalid crededidentials" });
            }
            res.redirect('/homepage');
        });
    })(req, res, next);
});

app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"]
}));

// Initialize google authentication strategy
app.get("/auth/google/homepage", (req, res, next) => {
    passport.authenticate('google', (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.status(401).render("login", {
                authenticationError: true,
                err: "Authentication failed"
            });
        }
        req.login(user, err => {
            if (err) {
                return next(err);
            }
            res.redirect('/homepage');
        })
    })(req, res, next);
});

// Create strategy method for local login
passport.use('local', new Strategy(async (username, password, cb) => {
    // Check if user exists in database
    try {
        const result = await db.query("SELECT * FROM USERS WHERE email = $1", [username]);
        if (!result.rows[0].password) return cb(null, false);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            if (!user.password) return cb(null, false);
            const hashedPassword = user.password;
            bcrypt.compare(password, hashedPassword, (err, isMatch) => {
                if (err) return cb(err);
                if (isMatch) return cb(null, user);
                else return cb(null, false);
            })
        } else {
            return cb(null, false);
        }
    } catch (error) {
        // Database error
        return cb(error);
    }
}));

// Register new authentication strategy for google
passport.use('google', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://linkedin-clone-swart-delta.vercel.app/auth/google/homepage"
}, async (accessToken, refreshToken, profile, cb) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
            const newUser = await db.query("INSERT INTO users (email, password) VALUES($1, $2) RETURNING *", [profile.email, null]);
            const user = newUser.rows[0];
            return cb(null, user);
        } else {
            // User already Exist in database
            const user = result.rows[0];
            return cb(null, user);
        }
    } catch (err) {
        return cb(err);
    }
}));

// Store user into session
passport.serializeUser((user, cb) => {
    cb(null, user);
});

// Return user session 
passport.deserializeUser((user, cb) => {
    cb(null, user);
});

app.listen(PORT, () => {
    console.log(`Server is listening at PORT ${PORT}`);
});