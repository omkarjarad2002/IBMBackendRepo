const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
  },
  cpassword: {
    type: String,
  },
  file: {
    type: String,
  },
  isadmin: {
    type: Boolean,
    default: false,
  },
  date: {
    type: Date,
    default: Date.now,
  },
  tokens: [
    {
      refreshToken: {
        type: String,
        required: true,
      },
    },
  ],
});

//  We are hashing the password and securing it

userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 12);
    this.cpassword = await bcrypt.hash(this.cpassword, 12);
  }
  next();
});

//Generating the auth token by using jwt and sending to the usersSchema

userSchema.methods.generateAuthToken = async function () {
  try {
    let accessToken = jwt.sign({ _id: this._id }, process.env.SECRET_KEY, {
      expiresIn: "30min",
    });

    return accessToken;
  } catch (error) {
    console.log(error);
  }
};

userSchema.methods.generateAuthRefreshToken = async function () {
  try {
    let refreshToken = jwt.sign({ _id: this._id }, process.env.REFRESH_KEY, {
      expiresIn: "7d",
    });
    this.tokens = this.tokens.concat({ refreshToken: refreshToken });
    await this.save();

    return refreshToken;
  } catch (error) {
    console.log(error);
  }
};

const User = mongoose.model("USER", userSchema);
module.exports = User;
