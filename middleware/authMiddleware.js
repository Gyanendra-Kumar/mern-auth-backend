import asyncHandler from "express-async-handler";
import User from "../models/userModel.js";
import jwt from "jsonwebtoken";

// CHECKING USER IS LOGGED IN OR NOT
export const protect = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      res.status(401).json({ message: "Not authorized. Please login" });
      return;
    }

    // VERIFY TOKEN
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    // GET USER ID FROM TOKEN
    const user = await User.findById(verified.id).select("-password");

    if (!user) {
      res.status(404).json({ message: "User not found." });
    }

    // IF USER IS SUSPENDED
    if (user.role === "suspended") {
      res.status(400).json({
        message: "User has been suspended. Please contact support team.",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: "Not authorized. Please login" });
  }
});

// ADMIN ONLY
export const adminOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    res.status(401).json({ message: "Not authorized. Please login as admin" });
  }
});

// AUTHOR ONLY
export const authorOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role === "author" || req.user.role === "admin") {
    next();
  } else {
    res.status(401).json({
      message:
        "Not authorized. Please contact administrator for required access.",
    });
  }
});

// VERIFIED ONLY
export const verifiedOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.isVerified) {
    next();
  } else {
    res
      .status(401)
      .json({ message: "Not authorized, account is not verified" });
  }
});
