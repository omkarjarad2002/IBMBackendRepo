const mongoose = require("mongoose");

const bookMarkSchema = new mongoose.Schema({
  blogId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "BLOGS",
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },
  date: {
    type: Date,
    default: Date.now(),
  },
});

const BookMarkedSchema = mongoose.model("BOOKMARKEDSCHEMA", bookMarkSchema);
module.exports = BookMarkedSchema;
