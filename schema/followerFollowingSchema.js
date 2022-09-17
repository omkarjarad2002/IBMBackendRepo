const mongoose = require("mongoose");

const followerFollowingSchema = new mongoose.Schema({
  followerID: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },
  followingID: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },
  isSubscribed: {
    type: Boolean,
    default: false,
  },
  date: {
    type: Date,
    default: Date.now(),
  },
});

const FollowersFollowing = mongoose.model(
  "FOLLOWERSFOLLOWIGNS",
  followerFollowingSchema
);
module.exports = FollowersFollowing;
