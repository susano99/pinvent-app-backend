const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Please add a name"],
    },
    email: {
      type: String,
      required: [true, "Please add an email"],
      unique: true,
      trim: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        "Please enter a valid email",
      ],
    },
    password: {
      type: "string",
      required: [true, "Please add a password"],
      minLength: [6, "Password must be at least 6 characters"],
      //maxLength: [255, "Password must be at most 23 characters"],
    },
    photo: {
      type: "string",
      required: [true, "Please add a photo"],
      default: "https://i.ibb.co/4pDNDk1/avatar.png",
    },
    phone: {
      type: "string",
      default: "+234",
    },
    bio: {
      type: "string",
      maxLength: [250, "Bio must be at most 250 characters"],
      default: "bio",
    },
  },
  {
    timestamps: true,
  }
);

// Encrypt pass b4 saving to db
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  //Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salt);
  this.password = hashedPassword;
  next(); // next piece of code is executed
});

const User = mongoose.model("User", userSchema);
module.exports = User;
