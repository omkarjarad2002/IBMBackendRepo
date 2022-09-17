const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { json, response } = require("express");
const express = require("express");
const router = express.Router();
const multer = require("multer");
const crypto = require("crypto");
const path = require("path");
const passport = require("passport");
const { v4: uuidv4 } = require("uuid");
const { OAuth2Client } = require("google-auth-library");
const nodemailer = require("nodemailer");

require("../db/conn");
const User = require("../schema/userSchema");
const Blog = require("../schema/userBlog");
const FollowersFollowing = require("../schema/followerFollowingSchema");
const {
  findById,
  findByIdAndDelete,
} = require("../schema/followerFollowingSchema");

const authGoogleClient = new OAuth2Client(
  "75044728575-dgg9ak39mi03976k7qv9orq6gl5ng6ji.apps.googleusercontent.com"
);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "../uploads"));
  },
  filename: (req, file, cb) => {
    const uniqueFileName = `${Date.now()}-${crypto
      .randomBytes(6)
      .toString("hex")}${path.extname(file.originalname)}`;
    cb(null, uniqueFileName);
  },
});

const upload = multer({ storage });

//sending email verification code
router.post("/sendEmail", async (req, res) => {
  const { email } = req.body;
  let data = await User.findOne({ email });

  const responceType = {};

  if (data) {
    let otpcode = Math.floor(Math.random() * 10000 + 1);
    responceType.statusText = "Success";
    responceType.message = "Please check Your Email Id";

    /////////////////////////////////////////////////////////////////

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "jaradomkar1@gmail.com",
        pass: "Jarad@2432#1234567890",
      },
    });

    const mailOptions = {
      from: "jaradomkar1@gmail.com",
      to: req.body.email,
      subject: "One time verification OTP from Blog's",
      text: otpcode.toString(),
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log("error", error.message);
      } else {
        console.log("Email sent: " + info.response);
      }
    });
    let final__otp = otpcode.toString();
    res.status(200).json({ email, final__otp });

    //////////////////////////////////////////////////////////////////
  } else {
    responceType.statusText = "error";
    responceType.message = "Email Id not Exist";
  }
});

//change password route

router.post("/changePassword", async (req, res) => {
  let { otp, otpcode, email, password, cpassword } = req.body;
  let data = await User.findOne({ email: email });

  const responce = {};
  if (data && otp === otpcode) {
    let currentTime = new Date().getTime();
    let diff = data.expireIn - currentTime;

    if (diff < 0) {
      responce.message = "Token Expire";
      responce.statusText = "error";
      res.status(402).json(responce);
    } else {
      let user = await User.findOne({ email: email });
      user.password = password;
      user.cpassword = cpassword;

      password = await bcrypt.hash(user.password, 12);
      cpassword = await bcrypt.hash(user.cpassword, 12);
      user.save();
      responce.message = "Password changed Successfully";
      responce.statusText = "Success";
      res.status(200).json(responce);
    }
  } else {
    responce.message = "Invalid Otp";
    responce.statusText = "error";
    res.status(401).json(responce);
  }
});

//upload file route

router.post("/uploadfile", upload.single("file"), (req, res) => {
  const response = res.json({ file: req.file });
  console.log(response);
  return response;
});

//registration route

router.post("/register", async (req, res) => {
  const { name, email, password, cpassword } = req.body;

  if (!name || !email || !password || !cpassword) {
    return res.status(422).json({ message: "Unexpected error occured !!" });
  }

  try {
    const userExist = await User.findOne({ email: email });

    if (userExist) {
      return res.status(422).json({ message: "User already exist !!" });
    } else if (password != cpassword) {
      return res.status(422).json({ message: "Password are not matching !!" });
    } else {
      const user = new User({ name, email, password, cpassword });

      //data mongodb la save karya aadhi password secure kela aahe userSchama madhe by using bcryptjs

      await user.save();
      return res
        .status(201)
        .json({ message: "User registerd successfully !!" });
    }
  } catch (error) {
    console.log(error);
  }
});

//add users profile pic    --->for these path some error is occured check it

router.post("/uploadfile", upload.single("file"), (req, res) => {
  return res.json({ file: req.file });
});

router.post("/editprofileinfo/:id", async (req, res) => {
  const { name, email, file } = req.body;
  console.log(req.body);

  if (!name || !email || !file) {
    return res.status(422).json({ message: "Unprocesseble entity !" });
  }
  try {
    const userExist = await User.findById({ _id: req.params.id });

    if (!userExist) {
      return res.status(401).json({ message: "User not exists" });
    }

    const updateProfilePic = await User.findByIdAndUpdate(
      { _id: req.params.id },
      {
        $set: req.body,
      }
    );
    await updateProfilePic.save();
    console.log(updateProfilePic);
    return res.json(updateProfilePic);
  } catch (error) {
    console.log(error);
    return res.status(402).json({ message: "ERROR" });
  }
});

//signIn route

router.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(req.body);

    if (!email || !password) {
      return res.status(400).json({ message: "Invalid Credentials !" });
    }

    const userLogin = await User.findOne({ email: email });

    if (userLogin) {
      const isMatch = await bcrypt.compare(password, userLogin.password);
      const accessToken = await userLogin.generateAuthToken();
      const refreshToken = await userLogin.generateAuthRefreshToken();

      res.cookie("jwttokenAccessToken", accessToken, {
        expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
        httpOnly: true,
      });

      res.cookie("jwttokenRefreshToken", refreshToken, {
        expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
        httpOnly: true,
      });

      if (!isMatch) {
        return res.status(401).json({ message: "Unauthorized !" });
      }

      if (userLogin) {
        return res.status(201).json({ userLogin, accessToken, refreshToken });
      }
    } else {
      return res.status(400).json({ message: "Invalid Credentials !" });
    }
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Failed to signIn !!" });
  }
});

//logout route

router.get("/logout", (req, res) => {
  res.clearCookie("jwttokenRefreshToken", { path: "/" });
  res.clearCookie("jwttokenAccessToken", { path: "/" });
  res.status(200).json("User logout");
});

//refresh token route

router.get("/refreshtoken", async (req, res) => {
  const { jwttokenRefreshToken } = req.cookies;

  if (!jwttokenRefreshToken) {
    return res.status(401).json({ message: "ERROR " });
  }

  try {
    const tokenData = jwt.verify(jwttokenRefreshToken, process.env.REFRESH_KEY);
    const user = await User.findOne({ _id: tokenData._id });
    if (!user) {
      return res.status(400).json({ message: "ERROR 1" });
    }

    return res.status(200).json({ user });
  } catch (error) {
    return res.status(401).json({ message: error });
  }
});

//addblog route

router.post("/addblog", async (req, res) => {
  const { title, description, blogType, userID, file } = req.body;
  console.log(req.body);

  try {
    const userExist = await User.findOne({ _id: userID });

    if (!userExist) {
      return res.status(401).json({ message: "User not found !" });
    }

    const newBlog = new Blog({
      title,
      description,
      blogType,
      userID,
      file,
    });

    await newBlog.save();
    return res.status(201).json({ newBlog });
  } catch (error) {
    return res.status(401).json({ message: error });
  }
});

//get all blogs

router.get("/getallblogs", async (req, res) => {
  const data = await Blog.find();
  return res.status(201).json({ data });
});

//get all blogs of specific user id these is only for that specific user

router.get("/getuserblogs/:id", async (req, res) => {
  const data = await Blog.find({ userID: req.params.id });
  return res.status(201).json({ data });
});

//update a specific user blog useing blog id

router.put("/updateblog/:id", async (req, res) => {
  const blog = await Blog.findOneAndUpdate(
    { _id: req.params.id },
    { $set: req.body }
  );
  return res.json(blog);
});

//delete a specific blog by blog id

router.delete("/deleteblog/:id", async (req, res) => {
  const data = await Blog.findByIdAndDelete({ _id: req.params.id });
  return res.json(data);
});

//add follower and following

router.post("/addfollowerfollowing", async (req, res) => {
  const { followerID, followingID } = req.body;

  try {
    const data = new FollowersFollowing({ followerID, followingID });
    console.log(data);
    await data.save();
  } catch (error) {
    console.log(error);
    return res.status(402).json({ message: "ERROR" });
  }
});

//get all followers to a specific user

router.get("/getallfollowers", async () => {
  const { followerID, followingID } = req.body;

  try {
    const data = await findById({ followerID, followingID });
    return res.json(data);
  } catch (error) {
    console.log(error);
  }
});

//unfollow the author
router.delete("/removefollowing", async () => {
  const { followerID, followingID } = req.body;

  try {
    const data = await findByIdAndDelete({ followerID, followingID });
    return res.json(data);
  } catch (error) {
    console.log(error);
  }
});

//googlelogin route

const CLIENT_URL = "http://localhost:3000/addPassword";

router.get("/login/failed", (req, res) => {
  return res.status(401).json({ success: false, message: "failure" });
});

router.get("/login/success", async (req, res) => {
  if (req.user) {
    return res.status(200).json({
      success: true,
      message: "success",
      user: req.user,
    });
  }
});

router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/google/callback",
  passport.authenticate("google", {
    successRedirect: CLIENT_URL,
    failureRedirect: "/login/failed",
    scope: ["profile", "email"],
  })
);

router.post("/addPassword/:id", async (req, res) => {
  const { password, cpassword } = req.body;

  if (!password || !cpassword) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const data = await User.findById({ _id: id });
  } catch (error) {
    return res.status(401).json({ message: "ERROR" });
  }
});

//get a specific blog
router.post("/specificBlogs", async (req, res) => {
  const { value } = req.body;
  console.log(value);
  const data = await Blog.find({ blogType: value });
  return res.status(201).json({ data });
});

module.exports = router;
