import { sendEmail } from "../config/sendEmail.js";
import asyncHandler from "express-async-handler";
import User from "../models/userModel.js";
import Token from "../models/tokenModel.js";
import crypto from "crypto";
import { hashToken } from "../config/generateToken.js";

// Send Automated emails
export const sendAutomatedEmails = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, template, url } = req.body;

  if (!subject || !send_to || !reply_to || !template) {
    res.sendStatus(500);
    throw new Error("Missing email parameter");
  }

  // Get user
  const user = await User.findOne({ email: send_to });

  if (!user) {
    res.sendStatus(404);
    throw new Error("User not found");
  }

  const sent_from = process.env.EMAIL_USER;
  const name = user.name;
  const link = `${process.env.FRONTEND_URL}${url}`;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: "Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

// SEND VERIFICATION EMAIL
export const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  if (user.isVerified) {
    res.status(400).json({ message: "User already verified" });
    return;
  }

  //   DELETE TOKEN IF IT EXISTS IN DB
  let token = await Token.findOne({ userId: user._id });

  if (token) {
    await token.deleteOne();
  }

  //   CREATE VERIFICATION TOKEN AND SAVE IT IN DB
  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;

  // HASH TOKEN AND SAVE IT IN DB
  const hashedToken = hashToken(verificationToken);

  await new Token({
    userId: user._id,
    verifyToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 1000 * 60 * 60, // 60 mins
  }).save();

  //   CONSTRUCT VERIFICATION URL
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

  // SEND EMAIL
  const subject = "Verify your account - Auth:Z";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "no-reply@outlook.com";
  const template = "verifyEmail";
  const name = user.name;
  const link = verificationUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: "Verification Email Sent" });
  } catch (error) {
    res.sendStatus(500);
    throw new Error("Email not sent, please try again");
  }
});

// VERIFY USER
export const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  // hashed token from DB
  const hashedToken = hashToken(verificationToken);
  const userToken = await Token.findOne({
    verifyToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    return res.status(404).json({ message: "Invalid or Expired token" });
  }

  // Find User
  const user = await User.findOne({ _id: userToken.userId });

  if (user.isVerified) {
    return res.status(400).json({ message: "User is already verified" });
  }

  // VERIFY USER
  user.isVerified = true;
  await user.save();
  return res
    .status(200)
    .json({ message: "User has been verified successfully" });
});
