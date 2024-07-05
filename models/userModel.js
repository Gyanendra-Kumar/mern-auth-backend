import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const { Schema } = mongoose;

const userSchema = Schema(
  {
    name: {
      type: String,
      required: [true, "Please add name"],
    },
    email: {
      type: String,
      required: [true, "Please add email"],
      unique: true,
      trim: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        "Please enter a valid email",
      ],
    },
    password: {
      type: String,
      required: [true, "Please add password"],
      validate: {
        validator: (value) => {
          const hasUppercase = /[A-Z]/.test(value);
          const hasLowercase = /[a-z]/.test(value);
          const hasNumber = /\d/.test(value);
          const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(value);
          const hasLength = value.length > 9;
          return (
            hasUppercase && hasLowercase && hasNumber && hasSpecial && hasLength
          );
        },
        message:
          "Password must contain an uppercase letter, a lowercase letter, a number, a special character, and minimum 10 characters",
      },
    },
    photo: {
      type: String,
      required: [true, "Please add photo"],
      default:
        "https://images.pexels.com/photos/415829/pexels-photo-415829.jpeg",
    },
    phone: {
      type: String,
      default: "+91-",
    },
    bio: {
      type: String,
      default: "Tell me about yourself",
    },
    role: {
      type: String,
      required: true,
      default: "subscriber",
      enum: ["subscriber", "author", "admin", "suspended"],
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    userAgent: {
      type: [String],
      required: true,
      default: [],
    },
    createdAt: {
      type: Date,
      default: Date.now(),
    },
    updatedAt: {
      type: Date,
      default: Date.now(),
      index: true,
    },
  },
  {
    timestamps: true,
    minimize: false,
  }
);

// Encrypt password before saving to DB
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salt);
  this.password = hashedPassword;
  next();
});

const User = mongoose.model("User", userSchema);

export default User;
