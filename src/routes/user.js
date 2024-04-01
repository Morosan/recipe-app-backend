import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { body, validationResult } from "express-validator";
import dotenv from "dotenv";
import winston from "winston";
import rateLimit from "express-rate-limit";

dotenv.config();

const router = express.Router();
import { UserModel } from "../models/Users.js";

const jwtSecret = process.env.JWT_SECRET;

// Configure winston logger
const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

if (process.env.NODE_ENV !== "production") {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong" });
};

router.use(errorHandler); // Mount the error handling middleware

// Logging middleware
router.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`);
  next();
});

// Regular expression for password complexity
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === "development" ? 1000 : 100, // allow higher rate limit during development
});

router.post(
  "/register",
  limiter,
  [
    body("username").trim().notEmpty().withMessage("Username is required"),
    body("password")
      .trim()
      .matches(passwordRegex)
      .withMessage(
        "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character"
      ),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error("Validation error:", errors.array());
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, password } = req.body;

      const user = await UserModel.findOne({ username });
      if (user) {
        logger.error("Username already exists:", username);
        return res.status(400).json({ message: "Username already exists" });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new UserModel({ username, password: hashedPassword });
      await newUser.save();
      logger.info("User registered successfully:", username);
      res.json({ message: "User registered successfully" });
    } catch (err) {
      logger.error("Error registering user:", err.message);
      next(err); // Pass the error to the error handling middleware
    }
  }
);

router.post(
  "/login",
  [
    body("username").trim().notEmpty().withMessage("Username is required"),
    body("password").trim().notEmpty().withMessage("Password is required"),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, password } = req.body;

      const user = await UserModel.findOne({ username });

      if (!user) {
        return res
          .status(400)
          .json({ message: "Username or password is incorrect" });
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res
          .status(400)
          .json({ message: "Username or password is incorrect" });
      }
      const token = jwt.sign({ id: user._id }, jwtSecret);
      res.json({ token, userID: user._id });
    } catch (err) {
      next(err); // Pass the error to the error handling middleware
    }
  }
);

export { router as userRouter };

export const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    jwt.verify(authHeader, jwtSecret, (err) => {
      if (err) {
        return res.sendStatus(403);
      }
      next();
    });
  } else {
    res.sendStatus(401);
  }
};