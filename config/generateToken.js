import jwt from "jsonwebtoken";
import crypto from "crypto";

// GENERATE TOKEN
export const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
};

// HASH TOKEN
export const hashToken = (token) => {
  return crypto.createHash("sha256").update(token.toString()).digest("hex");
};
