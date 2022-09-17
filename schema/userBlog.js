const mongoose = require("mongoose");

const userBlog = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },

  blogType: {
    type: String,
    required: true,
  },
  userID: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },
  file: {
    type: String,
    required: true,
  },
  date: {
    type: Date,
    default: Date.now(),
  },
});

const Blog = mongoose.model("BLOGS", userBlog);
module.exports = Blog;
