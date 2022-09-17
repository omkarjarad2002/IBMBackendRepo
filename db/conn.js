const mongoose = require("mongoose");
require("dotenv").config();
const DB = process.env.DATABASE;

const connection = async (req, res) => {
  try {
    const response = await mongoose.connect(DB);

    if (response) {
      console.log("Connection successfull");
    }
  } catch (error) {
    console.log(error);
  }
};

module.exports = { connection };
