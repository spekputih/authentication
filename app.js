//jshint esversion:6
require('dotenv').config()
const express = require("express")
const mongoose = require("mongoose")
const ejs = require("ejs")
const bodyParser = require("body-parser")
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

mongoose.set('useNewUrlParser', true);
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);
mongoose.set('useUnifiedTopology', true);

const app = express()

app.use(express.static("public"))
app.set("view engine", "ejs")
app.use(bodyParser.urlencoded({extended:true}))

app.use(session({
	secret: "this is our little secrets",
	resave: false,
	saveUninitialized: false
}))
 
app.use(passport.initialize())
app.use(passport.session())
//establish the connection with the database
mongoose.connect("mongodb://localhost:27017/authDB")


//create user schema
const userSchema = new mongoose.Schema({
	email: String,
	password: String,
	googleId: String,
	secret: String
})


userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

//create model
const User = mongoose.model("User", userSchema)

passport.use(User.createStrategy())
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//GET method
app.get("/", function(req, res){
	res.render("home")
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }))

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/register", function(req, res){
	res.render("register")
})
app.get("/login", ensureLoginAuthenticate, function(req, res){

	res.render("login")
})

app.get("/secrets", function(req, res){
	
	User.find({secret: {$ne: null}}, function(err, result){
		if(err){
			console.log(err)
		}else{
			res.render("secrets", {
				secrets: result
			})
		}
	})

})

app.get("/submit", ensureAuthenticated, function(req, res){
	res.render("submit")
})

//POST method
app.post("/register", function(req, res){
	User.register({username:req.body.username, active: true},
	 req.body.password, function (err, user){
		if(err){
			console.log(err)
				res.redirect("/register")
		}else{
			passport.authenticate("local")(req, res, function(){
				
			res.redirect("/secrets")
			
			})
		}
	})
})

app.post("/login", function (req, res){
	
	const user = new User({
		email: req.body.username,
		password: req.body.password
	})

	req.logIn(user, function(err){
		if(err){
			console.log(err)
			res.redirect("login")
		}else{
			passport.authenticate("local")(req, res, function(){
				res.redirect("/secrets")
			})
		}
	})

})

function ensureLoginAuthenticate(req, res, next){
	if(req.isAuthenticated()){
		res.redirect("/secrets")
	}else{
		return next()
	}
}

function ensureAuthenticated(req, res, next){
	if(req.isAuthenticated()){
		return next()
	}else{
		res.redirect("/login")
	}
}

app.post("/submit", function(req, res){
	let submitted = req.body.secret
	console.log(submitted)
	User.findById(req.user.id, function(err, result){
		if(err){
			console.log(err)
		}else{
			if(result){
				result.secret = submitted
				result.save(function(){
					res.redirect("/secrets")
				})
				console.log(result.secret)
			}
		}
	})	
})


app.get("/logout", function(req, res){
	req.logout()
	res.redirect("/")
})

app.listen(3000, function(){
	console.log("the application is served on port 3000")
})