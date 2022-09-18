const dotenv = require("dotenv");
const express = require("express");
const app = express();
const path = require("path");
const mongoose = require("mongoose");
dotenv.config({ path: "./env" });
const passport = require("passport");
const { connection } = require("../db/conn");
const passportSetup = require("../passport");
connection();

const expressSession = require("express-session");

const cookieParser = require("cookie-parser");
app.use(cookieParser());

app.use("/uploads", express.static(path.join(__dirname, "../uploads")));

const bodyParser = require("body-parser");
app.use(bodyParser.json());

app.use(
  expressSession({
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true },
    secret: "OMKARRITESHROHIT",
  })
);

app.use(passport.initialize());
app.use(passport.session());

const cors = require("cors");
app.use(
  cors({
    origin: "http://localhost:3000",
    methods: "GET,POST,DELETE,PUT,UPDATE",
    credentials: true,
  })
);
app.use(require("../router/auth"));

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`server listening on port ${PORT}`);
});
