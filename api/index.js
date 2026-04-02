import express from "express";
import bcrypt from "bcrypt";
import pg from "pg";
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";
import { v2 as cloudinary } from "cloudinary";
import multer from "multer";
import path from "path";

// Initialize env config in project
env.config();
const app = express();
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

// Initialize passport
app.use(passport.initialize());
app.use(passport.session());

// VERCEL FIX: Replace top-level await with a lazy async getDb() function.
// Top-level await crashes Vercel serverless functions. This pattern safely
// reuses a single connection across warm invocations via global.db.
async function getDb() {
    if (!global.db) {
        global.db = new pg.Client({
            connectionString: process.env.SUPABASE_CONNECTION_STRING,
            ssl: { rejectUnauthorized: false }
        });
        await global.db.connect();
    }
    return global.db;
}

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure multer to use memory storage
const upload = multer({ storage: multer.memoryStorage() });

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(process.cwd(), "public")));
app.set("views", path.join(process.cwd(), "views"));
app.set("view engine", "ejs");

// ─── Routes ──────────────────────────────────────────────────────────────────

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
        const db = await getDb();

        // Pagination — avoids loading all images into memory at once
        const page = parseInt(req.query.page) || 1;
        const limit = 20;
        const offset = (page - 1) * limit;

        const result = await db.query(
            "SELECT image_url FROM images ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            [limit, offset]
        );

        const images = result.rows.map(row => row.image_url);
        res.render('homepage.ejs', { images, page });

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
        if (err) return next(err);
        res.redirect('/login');
    });
});

// Authentication guard middleware
function requireAuth(req, res, next) {
    if (!req.isAuthenticated()) {
        return res.status(401).redirect('/login');
    }
    next();
}

app.post('/upload', requireAuth, upload.single('image'), async (req, res) => {
    try {
        const file = req.file;

        if (!file) {
            return res.status(400).send("No file uploaded");
        }

        const b64 = Buffer.from(file.buffer).toString("base64");
        const dataURI = `data:${file.mimetype};base64,${b64}`;

        const uploadResult = await cloudinary.uploader.upload(dataURI, {
            folder: "uploads"
        });

        const db = await getDb();
        await db.query(
            "INSERT INTO images (image_url) VALUES ($1)",
            [uploadResult.secure_url]
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
        const db = await getDb();

        const existing = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (existing.rows.length > 0) {
            return res.render("register", { error: "User already exists.", duplicateUser: true });
        }

        bcrypt.hash(password, saltRounds, async (err, hash) => {
            if (err) {
                console.error("Error hashing password:", err);
                return res.status(500).send("Registration failed");
            }

            try {
                const result = await db.query(
                    "INSERT INTO users (email, password) VALUES($1, $2) RETURNING *",
                    [email, hash]
                );
                const user = result.rows[0];
                req.login(user, err => {
                    if (err) {
                        console.error(err);
                        return res.status(500).send("Login after registration failed");
                    }
                    res.redirect("/homepage");
                });
            } catch (err) {
                console.error(err);
                res.status(500).send("Registration failed");
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Registration failed");
    }
});

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return res.status(500).render('login.ejs', { userNotFound: true, error: "Server error during login" });
        }
        if (!user) {
            return res.render('login.ejs', { userNotFound: true, error: "Invalid credentials" });
        }
        req.login(user, err => {
            if (err) {
                return res.status(500).render('login.ejs', { userNotFound: true, error: "Invalid credentials" });
            }
            res.redirect('/homepage');
        });
    })(req, res, next);
});

app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"]
}));

app.get("/auth/google/homepage", (req, res, next) => {
    passport.authenticate('google', (err, user, info) => {
        if (err) return next(err);
        if (!user) {
            return res.status(401).render("login", {
                authenticationError: true,
                err: "Authentication failed"
            });
        }
        req.login(user, err => {
            if (err) return next(err);
            res.redirect('/homepage');
        });
    })(req, res, next);
});

// ─── Passport Strategies ──────────────────────────────────────────────────────

passport.use('local', new Strategy(async (username, password, cb) => {
    try {
        const db = await getDb();
        const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);

        // Check user exists BEFORE accessing rows[0]
        if (result.rows.length === 0) return cb(null, false);

        const user = result.rows[0];

        // Handle Google OAuth users who have no password set
        if (!user.password) return cb(null, false);

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return cb(err);
            if (isMatch) return cb(null, user);
            else return cb(null, false);
        });
    } catch (error) {
        return cb(error);
    }
}));

passport.use('google', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL  // e.g. https://your-app.vercel.app/auth/google/homepage
}, async (accessToken, refreshToken, profile, cb) => {
    try {
        const db = await getDb();
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);

        if (result.rows.length === 0) {
            const newUser = await db.query(
                "INSERT INTO users (email, password) VALUES($1, $2) RETURNING *",
                [profile.email, null]
            );
            return cb(null, newUser.rows[0]);
        } else {
            return cb(null, result.rows[0]);
        }
    } catch (err) {
        return cb(err);
    }
}));

// Serialize only the user ID into the session
passport.serializeUser((user, cb) => {
    cb(null, user.id);
});

// Fetch fresh user from DB on each request using the stored ID
passport.deserializeUser(async (id, cb) => {
    try {
        const db = await getDb();
        const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
        if (result.rows.length === 0) return cb(null, false);
        cb(null, result.rows[0]);
    } catch (err) {
        cb(err);
    }
});

export default app;