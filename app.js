require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require('mongoose-encryption');
const md5 = require("md5");

const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({extended: true}));
app.use(express.static("public"));


mongoose.set("strictQuery", false);
mongoose.connect("mongodb://127.0.0.1:27017/userDB");



const userSchema = new mongoose.Schema({
  email: String,
  password: String
});



// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});



const User = new mongoose.model("User", userSchema);




app.get("/", function(req, res) {
  res.render("home");
});


app.get("/login", function(req, res) {
  res.render("login");
});


app.get("/register", function(req, res) {
  res.render("register");
});


app.post("/register", function(req, res) {
  const newUser = new User({
    email: req.body.username,
    password: md5(req.body.password)
  });
  newUser.save(function(err) {
    if (!err) {
      res.render("secrets");
    } else {
      console.log(err);
    }
  });
});

app.post("/login", function(req, res) {
  const email = req.body.username;
  const password = md5(req.body.password);
  User.findOne({email: email}, function(err, result) {
    if (err) {
      console.log(err);
    } else {
      if (result) {
        if(result.password === password) {
          res.render("secrets");
        }
      }
    }
  });


});












app.listen(3000, function() {
  console.log("server is running");
});