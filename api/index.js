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
app.use(passport.session());

// FIX #2: Top-level await requires "type": "module" in package.json.
// The db connection logic is preserved but wrapped in a safe initializer.
let db;

if (!global.db) {
    global.db = new pg.Client({
        connectionString: process.env.SUPABASE_CONNECTION_STRING,
        ssl: { rejectUnauthorized: false }
    });
    await global.db.connect();
}

db = global.db;

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
        // FIX #7: Added LIMIT and OFFSET for pagination to avoid loading all images
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
        if (err) {
            return next(err);
        }
        res.redirect('/login');
    });
});

// FIX #4: Added authentication guard to /upload route
app.post('/upload', (req, res, next) => {
    if (!req.isAuthenticated()) {
        return res.status(401).redirect('/login');
    }
    next();
}, upload.single('image'), async (req, res) => {
    try {
        const file = req.file;

        if (!file) {
            return res.status(400).send("No file uploaded");
        }

        // Convert buffer to base64
        const b64 = Buffer.from(file.buffer).toString("base64");
        const dataURI = `data:${file.mimetype};base64,${b64}`;

        const result = await cloudinary.uploader.upload(dataURI, {
            folder: "uploads"
        });

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

// FIX #5: Fixed typos in error messages
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

// FIX #3: Callback URL should come from environment variable to match actual deployment
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
        });
    })(req, res, next);
});

// ─── Passport Strategies ──────────────────────────────────────────────────────

// FIX #1: Moved rows.length check BEFORE accessing rows[0]
passport.use('local', new Strategy(async (username, password, cb) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);

        // Check user exists first before accessing rows[0]
        if (result.rows.length === 0) return cb(null, false);

        const user = result.rows[0];

        // Handle Google OAuth users who have no password
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

// FIX #3: Callback URL now reads from environment variable
passport.use('google', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL // Set this in your .env file
}, async (accessToken, refreshToken, profile, cb) => {
    try {
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

// FIX #6: Serialize only user ID, deserialize by fetching from DB
passport.serializeUser((user, cb) => {
    cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
        if (result.rows.length === 0) return cb(null, false);
        cb(null, result.rows[0]);
    } catch (err) {
        cb(err);
    }
});

export default app;