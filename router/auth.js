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
const sgMail = require("@sendgrid/mail");
const EMAIL_API_KEY = process.env.SENDGRID_API_KEY;
const SECRET_KEY = process.env.SECRET_KEY;
sgMail.setApiKey(EMAIL_API_KEY);

require("../db/conn");
const User = require("../schema/userSchema");
const Blog = require("../schema/userBlog");

const { appendFile } = require("fs");
const BookMarkedBlogs = require("../schema/bookMarkSchema");

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
  console.log(email);
  // res.send(email);

  let user = await User.findOne({ email });

  const responceType = {};

  if (user) {
    const secret = SECRET_KEY + user._id;
    console.log(secret);
    responceType.statusText = "Success";
    responceType.message = "Please check Your Email Id";

    const payload = {
      email: email,
      id: user._id,
    };

    const token = jwt.sign(payload, secret, { expiresIn: "15m" });
    console.log(token);
    const link = `http://localhost:3000/addPassword/${user._id}/${token}`;

    /////////////////////////////////////////////////////////////////

    const message = {
      to: req.body.email,
      from: "jaradomkar1@gmail.com",
      subject: "Password reset link from blog's",
      text: "Wish you a happy day with B's",
      html: `<Link> ${link} </Link>`,
    };

    sgMail
      .send(message)
      .then((response) => console.log(response))
      .catch((error) => console.log(error.message));

    return res.status(200).json({ message: "success" });

    //////////////////////////////////////////////////////////////////
  } else {
    responceType.statusText = "error";
    responceType.message = "Email Id not Exist";
  }
});

//verify otp route
router.post("/verifyotp", async (req, res) => {
  const { id, token } = req.params;

  if (!id || !token) {
    return;
  }

  try {
    const user = await User.findOne({ email });
    const secret = SECRET_KEY + user.password;

    const payload = jwt.verify(secret, token);
  } catch (error) {
    return res.status(400).json({ message: error });
  }
});

//change password route

router.post("/changePassword/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  let { password, cpassword } = req.body;
  const user = await User.findOne({ id: id });

  const responce = {};
  try {
    if (user) {
      const secret = SECRET_KEY + id;
      console.log(secret);
      const payload = jwt.verify(token, secret);

      user.password = password;
      user.cpassword = cpassword;
      res.send(user);

      password = await bcrypt.hash(user.password, 12);
      cpassword = await bcrypt.hash(user.cpassword, 12);
      await user.save();
      responce.message = "Password changed Successfully";
      responce.statusText = "Success";
      console.log(responce);
      res.status(200).json({ user });
    } else {
      responce.message = "Invalid Reset Link";
      responce.statusText = "error";
      res.status(401).json(responce);
    }
  } catch (error) {
    return res.status(500).json({ message: error });
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
      return res.status(201).json({ user });
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
    // const userLogin = await User.findOne({ email: email }).select("+password");

    if (userLogin) {
      console.log(userLogin);
      const isMatch = bcrypt.compare(password, userLogin.password);
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

//get user all blogs

router.get("/getUserAllblogs/:id", async (req, res) => {
  const data = await Blog.find({ userID: req.params.id });
  return res.status(201).json({ data });
});

//get blog
router.get("/getblogDetail/:id", async (req, res) => {
  const data = await Blog.findOne({ _id: req.params.id });
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

//get all book marked blogs of specific user
router.get("/getbookmarkedblogs/:id", async (req, res) => {
  const data = await BookMarkedBlogs.find({
    userId: req.params.id,
  }).populate("blogId");
  console.log(data);
  return res.json({ data });
});

//remove blog from book marked page

router.delete("/removebookmarkedblog/:id", async (req, res) => {
  const data = await BookMarkedBlogs.findByIdAndDelete({ _id: req.params.id });
  return res.json(data);
});

//book mark route

router.post("/bookMark", async (req, res) => {
  const { blogId, userId } = req.body;
  if (!blogId || !userId) {
    return res.status(422).json({ message: "Unexpected error occured !!" });
  }

  try {
    const userExist = await User.findById({ _id: userId });
    if (userExist) {
      const data = new BookMarkedBlogs({ blogId: blogId, userId: userId });
      await data.save();
      return res.status(201).json({ data });
    }
    return res.status(401).json({ data });
  } catch (error) {
    console.log(error);
  }
});

// get all book marked users
router.get("/getAllBookMarkedUsers/:id", async (req, res) => {
  const data = await BookMarkedBlogs.find({ userId: req.params.id });
  return res.json({ data });
});

//get a specific blog
router.post("/specificBlogs", async (req, res) => {
  const { value } = req.body;
  console.log(value);
  const data = await Blog.find({ blogType: value });
  return res.status(201).json({ data });
});

module.exports = router;
