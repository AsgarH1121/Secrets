// require needed to use environment variables, should be as early as possible in the code
// REMEMBER TO ALWAYS GITIGNORE THE ENV FILE 
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// required to use encryption
//const encrypt = require("mongoose-encryption");

// required to use md5 hash
//const md5 = require("md5");

// required to use bcrypt salt/hash, a salt is a random string of chars and what is done is that
// the salt is appended to the password and the result is then hashed
// to the hash we append the same salt and rehash in every salt round to get a new hash
//const bcrypt = require('bcrypt');
//const saltRounds = 10; // the number of salt rounds to hash through

// required for passport/cookies/session
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

// set up sessions
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

// set up passport and initialize them to be used by app
app.use(passport.initialize());
app.use(passport.session());

// set up database, the .set() is there to avoid deprecation issues
mongoose.connect("mongodb://localhost:27017/secretsDB", 
    {useNewUrlParser: true, useUnifiedTopology: true}
);
mongoose.set("useCreateIndex", true);

// create schema for user table
const userSchema = new mongoose.Schema ({
    email: String,
    password: String
});

// setup passport-local-mongoose plugin to be used
userSchema.plugin(passportLocalMongoose); // this will salt/hash the passwords and save users into DB

// define a secret (any string) to be used to encrypt the password
    // this has now been done using environment variables instead
// plugin needs to be done before the model object is created
// 'secret' is defined in documentation and process.env.SECRET will grab SECRET from our .env
// added field parameter at the end to only encrypt the password and not the emails
// NOTE: mongoose-encrypt will always encrypt when user calls save() and decrypt when user calls find()
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

// create model object for user table
const User = new mongoose.model("User", userSchema);

// set up passport/passport-local configurations, SHOULD BE AFTER THE CREATION OF THE MODEL
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser()); // these steps only need to be done when using sessions
passport.deserializeUser(User.deserializeUser()); // these steps only need to be done when using sessions

app.get("/", function(req, res) {
    res.render("home");
});

app.route("/login")
    .get(function(req, res) {
        res.render("login");
    })
    .post(function(req, res) {
        // const username = req.body.username;
        // //const password = md5(req.body.password); // hash password using md5
        // const password = req.body.password;

        // // look for the user with given email and then check if password matches what is given
        // User.findOne({email: username}, function(err, foundUser) {
        //     if(err) {
        //         console.log(err);
        //     }
        //     else {
        //         if(foundUser) { // if a user with that email exists
        //             // at this point mongoose-encryption would have returned the password decrypted already
        //             // which is why we can compare the users typed password to the returned one
        //             // if(foundUser.password === password) { // check if the passwords maths
        //             //     res.render("secrets"); // if they do then render the secrets page
        //             // }

        //             // // the below lines are used to compare password to salted hashed password stored
        //             // bcrypt.compare(password, foundUser.password, function(err, result) {
        //             //     // result should be true or false
        //             //     if(result) { // user has correct password if result is true
        //             //         res.render("secrets");
        //             //     }
        //             // });
        //         }
        //     }
        // });

        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        // use passport to authenticate the user
        req.login(user, function(err) {
            if(err) {
                console.log(err);
            }
            else {
                passport.authenticate("local")(req, res, function() {
                    res.redirect("/secrets");
                });
            }
        });
    });

app.get("/secrets", function(req, res) {
    // check if user is authenticated i.e. already logged in and if they are then render secrets
    if(req.isAuthenticated()) {
        res.render("secrets");
    }
    else {
        res.redirect("/login");
    }
});

app.route("/register")
    .get(function(req, res) {
        res.render("register");
    })
    .post(function(req, res){
        // // store the salted hash as the password using bcrypt
        // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        //     const newUser = new User({
        //         email: req.body.username,
        //         password: hash // store the produced hash as the password
        //     });
    
        //     newUser.save(function(err) {
        //         if(err) {
        //             console.log(err);
        //         }
        //         else {
        //             res.render("secrets");
        //         }
        //     });
        // });

        // const newUser = new User({
        //     email: req.body.username,
        //     password: md5(req.body.password) // hash the password using md5
        //     //password: req.body.password
        // });

        // // at this point mongoose-encryption will save the password encrypted
        // newUser.save(function(err) {
        //     if(err) {
        //         console.log(err);
        //     }
        //     else {
        //         res.render("secrets");
        //     }
        // });

        // can call this register method because of the passport-local-mongoose module
        User.register({username: req.body.username}, req.body.password, function(err, user) {
            if(err) { 
                console.log(err); 
                res.redirect("/register");
            }
            else {
                passport.authenticate("local")(req, res, function() {
                    res.redirect("/secrets");
                });
            }
        });
    });


app.get("/logout", function(req, res) {
    req.logout(); // de-authenticate the user
    res.redirect("/");
});

app.listen(3000, function() {
    console.log("Server started on port 3000");
});