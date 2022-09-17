const dotenv = require("dotenv");
var GoogleStrategy = require("passport-google-oauth20").Strategy;
dotenv.config({ path: "/env" });
const User = require("./schema/userSchema");
const passport = require("passport");

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/google/callback",
    },
    async function (accessToken, refreshToken, profile, cb) {
      console.log(profile);

      try {
        const user = await User.findOne({ email: profile.emails[0].value });
        console.log(user);
        if (user) {
          cb(null, user);
          return;
        }

        const newUser = new User({
          name: profile.displayName,
          email: profile.emails[0].value,
        });

        await newUser.save();

        return cb(null, newUser);
      } catch (error) {
        console.log(error);
        cb(null, false);
        return;
      }
    }
  )
);

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});
