
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

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

// Website files are stored in the main project folder
app.use(express.static(path.join(__dirname, "..")));

// Backend health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "success",
    message: "TalantaTix server is running"
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`TalantaTix server running on port ${PORT}`);
});

