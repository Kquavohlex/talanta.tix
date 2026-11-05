
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
  console.error("Missing DATABASE_URL or JWT_SECRET environment variable.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

// Create the customer accounts table
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      phone VARCHAR(30) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      country VARCHAR(100) NOT NULL,
      age INTEGER NOT NULL,
      promo_code VARCHAR(50),
      role VARCHAR(20) NOT NULL DEFAULT 'customer',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

// Register a new customer
app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      phone,
      email,
      password,
      confirmPassword,
      country,
      age,
      promoCode
    } = req.body || {};

    if (!name || !phone || !email || !password || !country || !age) {
      return res.status(400).json({
        success: false,
        message: "Please complete all required fields."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 8 characters."
      });
    }

    if (confirmPassword && password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Passwords do not match."
      });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const cleanPhone = String(phone).trim();
    const cleanName = String(name).trim();
    const cleanCountry = String(country).trim();
    const numericAge = Number(age);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address."
      });
    }

    if (!Number.isInteger(numericAge) || numericAge < 1 || numericAge > 120) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid age."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
       (name, phone, email, password_hash, country, age, promo_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, name, phone, email, country, age, created_at`,
      [
        cleanName,
        cleanPhone,
        cleanEmail,
        passwordHash,
        cleanCountry,
        numericAge,
        promoCode ? String(promoCode).trim() : null
      ]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      { userId: user.id, role: "customer" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("talanta_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.status(201).json({
      success: true,
      message: "Account created successfully.",
      user
    });

  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        message: "That email address or phone number is already registered."
      });
    }

    console.error("Registration error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to create account. Please try again."
    });
  }
});

// Log in using email address or phone number
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, phone, identifier, password } = req.body || {};
    const loginId = String(identifier || email || phone || "")
      .trim()
      .toLowerCase();

    if (!loginId || !password) {
      return res.status(400).json({
        success: false,
        message: "Enter your email or phone number and password."
      });
    }

    const result = await pool.query(
      `SELECT id, name, phone, email, password_hash, country, age, role
       FROM users
       WHERE LOWER(email) = $1 OR phone = $2
       LIMIT 1`,
      [loginId, loginId]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        success: false,
        message: "Incorrect login details."
      });
    }

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("talanta_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    delete user.password_hash;

    return res.json({
      success: true,
      message: "Login successful.",
      user
    });

  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to log in. Please try again."
    });
  }
});

// Log out
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("talanta_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax"
  });

  res.json({ success: true, message: "Logged out." });
});

// Check whether the backend is running
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "TalantaTix backend is running."
  });
});

// Serve the website from the main repository folder
app.use(express.static(path.join(__dirname, "..")));

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`TalantaTix is running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Could not start TalantaTix:", error);
    process.exit(1);
  }
}

startServer();
