var express = require('express');
var router = express.Router();
var path = require('path');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var exphbs = require('express-handlebars');
var expressValidator = require('express-validator');
var flash = require('connect-flash');
var session = require('express-session');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var mongo = require('mongodb');
var mongoose = require('mongoose');
var ejs = require('ejs');

const url = 'mongodb://localhost/loginapp';

mongoose.connect('mongodb://localhost/loginapp');

var db = mongoose.connection;

var routes = require('./routes/index');

var users = require('./routes/users');
var students = require('./routes/students');
var fee = require('./routes/fee');

// Init App
var app = express();

// View Engine
app.set('views', path.join(__dirname, 'views'));
app.use('/assets', express.static(__dirname + '/public'));

app.set('view engine','ejs');
//app.engine('handlebars', exphbs({defaultLayout:'layout'}));
//app.set('view engine', 'handlebars');

// BodyParser Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// Set Static Folder
app.use(express.static(path.join(__dirname, 'public')));

// Express Session
app.use(session({
    secret: 'secret',
    saveUninitialized: true,
    resave: true
}));

//csv 

app.use(session({ cookie: { maxAge: 60000 }, 

  secret: 'secret',

  resave: false, 

  saveUninitialized: false}));

// Passport init
app.use(passport.initialize());
app.use(passport.session());

// Express Validator
app.use(expressValidator({
  errorFormatter: function(param, msg, value) {
      var namespace = param.split('.')
      , root    = namespace.shift()
      , formParam = root;

    while(namespace.length) {
      formParam += '[' + namespace.shift() + ']';
    }
    return {
      param : formParam,
      msg   : msg,
      value : value
    };
  }
}));

// Connect Flash
app.use(flash());

router.get('/logout', function (req, res) {
  req.logout();

  
  req.session.destroy();
  res.redirect('/users/login');
});

// Global Vars
app.use(function (req, res, next) {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  res.locals.user = req.user || null;
  next();
});



app.use('/', routes);

app.use('/users', users);
app.use('/students',students);
app.use('/fee',fee);

// Set Port
app.set('port', (process.env.PORT || 4000));

app.listen(app.get('port'), function(){
	console.log('Server started on port '+app.get('port'));
});