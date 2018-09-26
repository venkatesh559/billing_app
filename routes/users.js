var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var MongoClient = require('mongodb').MongoClient;
var bcrypt = require('bcryptjs');




var User = require('../models/user');
var role;

this.rolepub = role;

//var url = "mongodb://127.0.0.1:27017/";
var url = "mongodb://localhost/loginapp";



// Register
//router.get('/register', function (req, res) {
//	res.render('register')

//});

// Login
router.get('/login', function (req, res) {
	res.render('login');
});

//change password

router.get('/changepass',function(req,res){
	res.render('changepass');
});




router.get('/employeedetails',function(req,res){
	res.render('employeedetails');
});

router.get('/viewemployee',function(req,res){
	res.render('viewemployee');
});
//Change password db

router.get('/deleteemployee',function(req,res){
	res.render('deleteemployee');
});
router.post('/changepass' , function(req,res){
	var username = req.body.username;
	var password1 = req.body.password1;
	var password2 = req.body.password2;

	

	var passwordhash = bcrypt.genSalt(10, function(err, salt) {
	    bcrypt.hash(password1, salt, function(err, hash) {
			passwordhash = hash;
		});
	});
	MongoClient.connect(url, function(err, db) {
  		if (err) throw err;
  		var dbo = db.db("loginapp");
  		var myquery = { username: req.body.username };
  		var newvalues = { $set: {password : passwordhash } };
  		dbo.collection("users").updateOne(myquery, newvalues, function(err, res) {
    		if (err) throw err;
    		console.log("1 document updated");
    		db.close();
  		});
	});
	req.flash('success_msg','password changed sucessfully login to continue');
	res.redirect('/users/login');
	
});

// Register User
router.post('/register', function (req, res) {
	var name = req.body.name;
	var phone = req.body.name;
	var roleid = req.body.roleid;
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	var password2 = req.body.password2;

	// Validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('username', 'Username is required').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

	var errors = req.validationErrors();

	if (errors) {
		res.render('register', {
			errors: errors
		});
	}
	else {
		//checking for email and username are already taken
		User.findOne({ username: { 
			"$regex": "^" + username + "\\b", "$options": "i"
	}}, function (err, user) {
			User.findOne({ email: { 
				"$regex": "^" + email + "\\b", "$options": "i"
		}}, function (err, mail) {
				if (user || mail) {
					res.render('register', {
						user: user,
						mail: mail
					});
				}
				else {
					var newUser = new User({
						name: name,
						email: email,
						username: username,
						password: password,
						name :name,
						phone:phone,
						roleid:roleid
					});
					User.createUser(newUser, function (err, user) {
						if (err) throw err;
						console.log(user);
					});
         	req.flash('success_msg', 'Employee is added');
					res.redirect('/');
				}
			});
		});
	}
});

passport.use(new LocalStrategy(
	function (username, password, done) {
		User.getUserByUsername(username, function (err, user) {
			if (err) throw err;
			if (!user) {
				return done(null, false, { message: 'Unknown User' });
			}

			User.comparePassword(password, user.password, function (err, isMatch) {
				if (err) throw err;
				if (isMatch) {
					return done(null, user);
				} else {
					return done(null, false, { message: 'Invalid password' });
				}
			});
		});
	}));

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.getUserById(id, function (err, user) {
		done(err, user);
	});
});

router.post('/viewempolyee',function(req,res){
	
		MongoClient.connect(url, function(err, db) {
			if (err) throw err;
			var dbo = db.db("loginapp");
		var emp = dbo.collection('users').find({username: req.body.username});
		emp.each(function(err,doc){
			if(doc!=null){
			console.log(doc);
			
		console.log(typeof doc);
		
			}
			
		});
	});
	
});
router.post('/deleteemployee',function(req,res){
	MongoClient.connect(url,function(err,db){
		if(err) throw err;
		var dbo = db.db("loginapp");
		var emp = dbo.collection('users').deleteOne({username : req.body.username});
		res.redirect('/deleteemployee');
	});
});

router.post('/login',
	passport.authenticate('local', { successRedirect: '/', failureRedirect: '/users/login', failureFlash: true }),
	function (req, res) {
		this.req = req

		console.log(this.req)
		
		//res.redirect('/');
	
});

router.get('/logout', function (req, res) {
	req.logout();

	
	req.session = null;
	res.redirect('/users/login');
});

module.exports = router;
module.exports.role = this.rolepub ;


