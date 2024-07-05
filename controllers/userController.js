import asyncHandler from "express-async-handler";
import User from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { generateToken, hashToken } from "../config/generateToken.js";
import parser from "ua-parser-js";
import UAParser from "ua-parser-js";
import Token from "../models/tokenModel.js";
import { sendEmail } from "../config/sendEmail.js";
import { cryptr } from "../config/excrypt.js";
import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// LOGIN USERS
export const loginController = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password) {
    return res.status(400).json({ message: "Please add email and password" });
  }

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ message: "User not found, please signup" });
  }

  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  if (!passwordIsCorrect) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  // Trigger 2FA for unknown UserAgent
  // const ua = parser(req.headers["user-agent"]);
  // const thisUserAgent = ua.ua;
  // console.log(thisUserAgent);
  // const allowedAgent = user.userAgent.includes(thisUserAgent);

  const parser = new UAParser();
  const ua = parser.setUA(req.headers["user-agent"]).getResult();
  const thisUserAgent = `${ua.browser.name} ${ua.browser.version}`;
  const allowedAgent = user.userAgent.includes(thisUserAgent);

  if (!allowedAgent) {
    // Generate 6 digit code
    const loginCode = Math.floor(100000 + Math.random() * 900000);

    // Encrypt login code before saving to DB
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

    // Delete Token if it exists in DB
    let userToken = await Token.findOne({ userId: user._id });
    if (userToken) {
      await userToken.deleteOne();
    }

    // Save Token to DB
    await new Token({
      userId: user._id,
      loginToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
    }).save();

    return res.status(400).json({ message: "New browser or device detected" });
  }

  // Generate Token
  const token = generateToken(user._id);

  // Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: "none",
    secure: true,
  });

  const {
    _id,
    name,
    email: userEmail,
    phone,
    bio,
    photo,
    role,
    isVerified,
  } = user;

  res.status(200).json({
    _id,
    name,
    email: userEmail,
    phone,
    bio,
    photo,
    role,
    isVerified,
    token,
  });
});

// REGISTER USERS
export const registerController = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  //   CHECKING FOR NAME, EMAIL AND PASSWORD ARE NOT EMPTY
  if (!name || !email || !password) {
    res
      .status(400)
      .json({ message: "Please fill in all the required fields." });
    return;
  }

  //   CHECKING FOR PASSWORD LENGTH LESS THAT 10 CHARACTERS
  if (password.length < 10) {
    res
      .status(400)
      .json({ message: "Password must be at least 10 characters." });
    return;
  }

  //   CHECKING IF USER EXISTS
  const userExists = await User.findOne({
    email,
  });

  if (userExists) {
    res.status(400).json({ message: "Email already in use." });
    return;
  }

  //   Get user agent
  // const ua = parser(req.headers["user-agent"]);
  // const userAgent = [ua.ua];
  // console.log(userAgent);
  const parser = new UAParser();
  const ua = parser.setUA(req.headers["user-agent"]).getResult();
  const userAgent = `${ua.browser.name} ${ua.browser.version}`;
  // console.log("Parsed User Agent:", thisUserAgent);
  // const allowedAgent = user.userAgent.includes(thisUserAgent);

  //   CREATE NEW USER
  const user = await User.create({
    name,
    email,
    password,
    userAgent,
  });

  //   GENERATE TOKEN
  const token = generateToken(user._id);

  //   SEND HTTP-ONLY COOKIE
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 Day
    sameSite: "none",
    secure: true,
  });

  //   SENDING RESPONSE TO USER
  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
      userAgent,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

// LOGOUT CONTROLLER
export const logoutController = asyncHandler(async (req, res) => {
  res.clearCookie("token");
  res.status(200).json({ message: "Successfully logged out" });
});

// GET USER
export const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res
      .status(200)
      .json({ _id, name, email, phone, bio, photo, role, isVerified });
  } else {
    res.status(404).json({ message: "User not found." });
  }
});

// UPDATE USER
export const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  if (req.body.name) {
    user.name = req.body.name;
  }

  if (req.body.role) {
    res
      .status(401)
      .json({ message: "Not authorized. Please contact administrator." });
    return;
  }

  if (req.body.phone) {
    user.phone = req.body.phone;
  }

  if (req.body.photo) {
    user.photo = req.body.photo;
  }
  if (req.body.bio) {
    user.bio = req.body.bio;
  }

  await user.save();

  res.status(200).json(user);
});

// DELETE USER
export const deleteUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  const loggedInUser = req.user.id;
  const userIdToDelete = req.params.id;

  if (userIdToDelete === loggedInUser) {
    res.status(400).json({ message: "You cannot delete yourself" });
    return;
  }

  console.log("User found", user);
  if (!user) {
    res.status(404).json({ message: "User not found" }); // Sending response with 404 status code and error message
    return;
  }

  await User.findByIdAndDelete(req.params.id);

  console.log("User deleted:", user);

  res.status(200).json({ message: "User has been deleted successfully" });
});

// GET ALL USERS
export const getUsers = asyncHandler(async (req, res) => {
  const users = await User.find().sort("createdAt").select("-password");

  if (!users) {
    res.status(404).json({ message: "No users found" });
    return;
  }

  res.status(200).json(users);
});

// LOGIN STATUS
export const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.json(false);
  }

  // verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);

  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});

// UPDATE USER ROLE
export const updateUserRole = asyncHandler(async (req, res) => {
  const { role, id } = req.body;

  const user = await User.findById(id);

  if (!user) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  user.role = role;

  await user.save();
  res.status(200).json({ message: `User role has been updated to ${role}` });
});

// FORGOT PASSWORD
export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  try {
    if (!email) {
      res.status(400);
      throw new Error("Email is required");
    }

    const user = await User.findOne({ email });
    if (!user) {
      res.status(404);
      throw new Error("No user with this email");
    }

    // Delete Token if it exists in DB
    let token = await Token.findOne({ userId: user._id });
    if (token) {
      await token.deleteOne();
    }

    // Create Verification Token and Save
    const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log("reset token: ", resetToken);

    // Hash token and save
    const hashedToken = hashToken(resetToken);
    console.log("hashed token: ", hashedToken);

    await new Token({
      userId: user._id,
      resetToken: hashedToken,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
    }).save();

    console.log("hashed token saved successfully");

    // Construct Reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

    // Send Email
    const subject = "Password Reset Request - Auth:Z";
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "no-reply@outlook.com";
    const template = "forgotPassword";
    const name = user.name;
    const link = resetUrl;

    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "Password Reset Email Sent" });
  } catch (error) {
    console.error("Error in forgotPassword:", error);
    res.status(500);
    res.json({ message: error.message });
  }
});

// Reset Password
export const resetPassword = asyncHandler(async (req, res) => {
  // res.send("reset password");

  const { resetToken } = req.params;
  console.log("reset Token: ", resetToken);

  const { password } = req.body;
  console.log("change password: ", password);

  const hashedToken = hashToken(resetToken);
  const userToken = await Token.findOne({
    resetToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    return res.sendStatus(404).json({ message: "Invalid or Expired token" });
  }

  const user = await User.findById({ _id: userToken.userId });
  console.log(("user details - reset token: ", user));

  // now reset password
  user.password = password;
  await user.save();

  res
    .status(200)
    .json({ message: "Password reset successful, Please login again" });
});

// CHANGE PASSWORD
export const changePassword = asyncHandler(async (req, res) => {
  // res.send("change password");
  const { oldPassword, password } = req.body;
  // console.log("old password: ", oldPassword);
  // console.log("new password: ", password);

  const user = await User.findById(req.user._id);
  console.log("user: ", req.user._id);

  if (!user) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  if (oldPassword === password) {
    res
      .status(400)
      .json({ message: "New password cannot be same as old password" });
    return;
  }

  if (!oldPassword || !password) {
    res
      .status(400)
      .json({ message: "Please provide old password and new password" });
    return;
  }

  // check if old password is correct
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  console.log("correct password: ", passwordIsCorrect);

  if (!passwordIsCorrect) {
    res
      .status(400)
      .json({ message: "Old password is not correct. Please try again" });
    return;
  }

  // save new password
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();

    res
      .status(200)
      .json({ message: "Password changed successfully. Please login again" });
  } else {
    res.status(400).json({ message: "Old password is incorrect" });
  }
});

// SEND LOGIN CODE
export const sendLoginCode = asyncHandler(async (req, res) => {
  // res.send("login code");
  const { email } = req.params;
  const user = await User.findOne({ email });
  // console.log("user: ", user);

  if (!user) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  // Find Login Code in DB
  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });
  // console.log("Token: ", userToken);

  const loginToken = userToken.loginToken;
  const decryptedLoginCode = cryptr.decrypt(loginToken);
  console.log("decrypted login code: ", decryptedLoginCode);

  // Send Login Code
  const subject = "Password Reset Request - Auth:Z";
  const send_to = email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "no-reply@outlook.com";
  const template = "loginCodes";
  const name = user.name;
  const link = decryptedLoginCode;

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
    res.status(200).json({ message: `Access code sent to ${email}` });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

// LOGIN WITH CODE
export const loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Find user Login Token
  const userToken = await Token.findOne({
    userId: user.id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token, please login again");
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.loginToken);

  console.log("login code after user enter: ", decryptedLoginCode);

  if (loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error("Incorrect login code, please try again");
  } else {
    // Register userAgent
    const parser = new UAParser();
    const ua = parser.setUA(req.headers["user-agent"]).getResult();
    const thisUserAgent = `${ua.browser.name} ${ua.browser.version}`;
    user.userAgent.push(thisUserAgent);

    console.log(thisUserAgent);
    await user.save();

    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});

// LOGIN WITH GOOGLE

// export const loginWithGoogle = asyncHandler(async (req, res) => {
//   const { userToken } = req.body;

//   // console.log("userToken: ", userToken);

//   const ticket = await client.verifyIdToken({
//     idToken: userToken,
//     audience: process.env.GOOGLE_CLIENT_ID,
//   });
//   const payload = ticket.getPayload();
//   console.log("payload from back: ", payload);
//   const { name, email, picture, sub } = payload;

//   // check if user exits
//   const user = await User.findOne({ email });

//   // if user does not exits, register new user

//   try {
//     if (!user) {
//       const password = Date.now() + sub;

//       // get user agent
//       const parser = new UAParser();
//       const ua = parser.setUA(req.headers["user-agent"]).getResult();
//       const userAgent = `${ua.browser.name} ${ua.browser.version}`;

//       // Register new user
//       const newUser = await User.create({
//         name,
//         email,
//         photo: picture,
//         password,
//         isVerified: true,
//         userAgent,
//       });

//       console.log("new user: ", newUser);

//       if (newUser) {
//         // generate token
//         const token = generateToken(user._id);

//         // send HTTP only
//         res.cookie("token", token, {
//           path: "/",
//           httpOnly: true,
//           expiresAt: new Date(Date.now() + 1000 * 86400), // 1 Day
//           sameSite: "none",
//           secure: true,
//         });

//         const { _id, name, email, isVerified, bio, photo, role, phone } =
//           newUser;

//         res.status(201).json({
//           _id,
//           name,
//           email,
//           isVerified,
//           bio,
//           photo,
//           role,
//           phone,
//           token,
//         });
//       }
//     }
//   } catch (error) {
//     res.status(500).json({ message: "Failed to register with Google" });
//   }

//   // if user exits
//   if (user) {
//     const token = generateToken(user._id);
//     // Send HTTP-only cookie
//     res.cookie("token", token, {
//       path: "/",
//       httpOnly: true,
//       expires: new Date(Date.now() + 1000 * 86400), // 1 day
//       sameSite: "none",
//       secure: true,
//     });

//     const { _id, name, email, phone, bio, photo, role, isVerified } = user;

//     res.status(201).json({
//       _id,
//       name,
//       email,
//       phone,
//       bio,
//       photo,
//       role,
//       isVerified,
//       token,
//     });
//   }
// });

export const loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body;

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();
  const { name, email, picture, sub } = payload;
  const password = Date.now() + sub;

  // Get UserAgent
  const parser = new UAParser();
  const ua = parser.setUA(req.headers["user-agent"]).getResult();
  const userAgent = `${ua.browser.name} ${ua.browser.version}`;

  // Check if user exists
  let user = await User.findOne({ email });

  if (!user) {
    res.status(500).json({ message: "User does not exits. Please register" });
    return;
    // Create new user
    // user = await User.create({
    //   name,
    //   email,
    //   password,
    //   photo: picture,
    //   isVerified: true,
    //   userAgent,
    // });
    // if (user) {
    //   // Generate Token
    //   const token = generateToken(user._id);
    //   // Send HTTP-only cookie
    //   res.cookie("token", token, {
    //     path: "/",
    //     httpOnly: true,
    //     expires: new Date(Date.now() + 1000 * 86400), // 1 day
    //     sameSite: "none",
    //     secure: true,
    //   });
    //   const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    //   return res.status(201).json({
    //     _id,
    //     name,
    //     email,
    //     phone,
    //     bio,
    //     photo,
    //     role,
    //     isVerified,
    //     token,
    //   });
    // } else {
    //   throw new Error("User creation failed");
    // }
  }

  // User exists, login
  if (user) {
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});
