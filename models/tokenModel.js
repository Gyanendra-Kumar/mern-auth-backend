import mongoose from "mongoose";

const tokenSchema = mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "user",
  },
  verifyToken: {
    type: "string",
    default: "",
  },
  resetToken: {
    type: "string",
    default: "",
  },
  loginToken: {
    type: "string",
    default: "",
  },
  createdAt: {
    type: Date,
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
});

const Token = mongoose.model("Token", tokenSchema);
export default Token;
