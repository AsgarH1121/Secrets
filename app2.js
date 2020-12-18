// require needed to use environment variables, should be as early as possible in the code
// REMEMBER TO ALWAYS GITIGNORE THE ENV FILE 
require('dotenv').config();

// THIS CODE WILL USE GOOGLE AUTHENTICATION SO MAKE SURE TO CREATE APP ON GOOGLE FIRST

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// required for passport/cookies/session
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// required for google authentication which we then use as a passport strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// required to make the findOrCreate method work down below
const findOrCreate = require('mongoose-findorcreate');

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
// set autoIndex to false to avoid errors with googleAuth
mongoose.connect("mongodb://localhost:27017/secretsDB", 
    {useNewUrlParser: true, useUnifiedTopology: true, autoIndex: false}
);
mongoose.set("useCreateIndex", true);

// create schema for user table
const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// setup passport-local-mongoose plugin to be used and also findorcreate
userSchema.plugin(passportLocalMongoose); // this will salt/hash the passwords and save users into DB
userSchema.plugin(findOrCreate);

// create model object for user table
const User = new mongoose.model("User", userSchema);

// set up passport/passport-local configurations, SHOULD BE AFTER THE CREATION OF THE MODEL
passport.use(User.createStrategy());

// set up how passport serializes and deserializes users, use code from passportjs documentation to work
// with all authentication strategies and not just local
passport.serializeUser(function(user, done) {
    done(null, user.id);
});
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
});

// tell passport to use the google auth, should be after the other passport stuff 
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id, username: profile.displayName }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
    res.render("home");
});

// authenticate user using passport, first parameter is strategy we want to use in authentication
// second parameter is what we want once we have authenticated the users google account, i.e. we want their profile
// which includes their email and googleID
app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] })
);

// set up route once google has authorized user
app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  }
);

app.route("/login")
    .get(function(req, res) {
        res.render("login");
    })
    .post(function(req, res) {
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
    // find all users with a secret and generate those secrets onto the secrets page
    // NOTE: the $ne: null means not equal to null and will return records where secret != null
    User.find({"secret": {$ne: null}}, function(err, foundUsers) {
        if(err) {
            console.log(err);
        }
        else {
            if(foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

app.route("/submit")
    .get(function(req, res) {
        // check if user is authenticated i.e. already logged in and if they are then let them submit secrets
        if(req.isAuthenticated()) {
            res.render("submit");
        }
        else {
            res.redirect("/login");
        } 
    })
    .post(function(req, res) {
        const submittedSecret = req.body.secret;

        User.findById(req.user.id, function(err, foundUser) {
            if(err) {
                console.log(err);
            }
            else {
                if(foundUser) {
                    foundUser.secret = submittedSecret;
                    foundUser.save(function(){
                        res.redirect("/secrets");
                    })
                }
            }
        });
    });

app.route("/register")
    .get(function(req, res) {
        res.render("register");
    })
    .post(function(req, res){
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