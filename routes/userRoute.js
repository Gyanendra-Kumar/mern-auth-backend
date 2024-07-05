import express from "express";
import {
  registerController,
  loginController,
  logoutController,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  updateUserRole,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
} from "../controllers/userController.js";

import {
  sendAutomatedEmails,
  sendVerificationEmail,
  verifyUser,
} from "../controllers/emailController.js";

import {
  adminOnly,
  authorOnly,
  protect,
} from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/register", registerController);
router.post("/login", loginController);
router.get("/logout", logoutController);
router.get("/getUser", protect, getUser);
router.patch("/updateUser", protect, updateUser);

// DELETE ROUTE
router.delete("/:id", protect, adminOnly, deleteUser);

// GET ALL USERS
router.get("/getUsers", protect, authorOnly, getUsers);

// LOGIN STATUS
router.get("/loginStatus", loginStatus);

// UPDATE ROLE
router.post("/updateRole", protect, adminOnly, updateUserRole);

// SEND AUTOMATED EMAILS
router.post("/sendAutomatedEmails", protect, sendAutomatedEmails);

// SEND VERIFICATION EMAIL
router.post("/sendVerificationEmail", protect, sendVerificationEmail);

// VERIFY USER
router.patch("/verifyUser/:verificationToken", verifyUser);

// FORGOT PASSWORD
router.post("/forgotPassword", forgotPassword);

// RESET PASSWORD
router.patch("/resetPassword/:resetToken", resetPassword);

// CHANGE PASSWORD
router.patch("/changePassword", protect, changePassword);

// SEND LOGIN CODE IN EMAIL
router.post("/sendLoginCode/:email", sendLoginCode);

// LOGIN WITH CODE
router.post("/loginWithCode/:email", loginWithCode);

// LOGIN WITH GOOGLE
router.post("/google/callback", loginWithGoogle);

export default router;
