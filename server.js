var express = require('express');
var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');
var passport = require('passport');
var jwt = require('jwt-simple');
var nodemailer = require('nodemailer');
var async = require('async');
var crypto = require('crypto');

//Database config
var config = require('./config/database');

//MongoDB Schema
var User = require('./app/models/user');
var Article = require('./app/models/article');

//Define our express app
var app = express();

//Define the port our server will run on
var port = process.env.PORT || 8080;
//var port = 80;

//Define email transporter;
var smtpTransport = nodemailer.createTransport(config.smtpConfig);


//Get our request parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

//app.use(express.static('./public')); 

//Log to console
app.use(morgan('dev'));

app.all('/*', function (req, res, next) {
  //CORS headers
  res.header("Access-Control-Allow-Origin", "*"); // restrict it to the required domain
  res.header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS");

  //Set Custom headers for CORS
  res.header('Access-Control-Allow-Headers', 'Authorization,Content-type,Accept,X-Access-Token,X-Key');
  if (req.method == 'OPTIONS') {
    res.status(200).end();
  }
  else {
    next();
  }
});

//Demo Route
app.get('/', function (req, res) {
  res.send('Hello! The app is at http://ballabove.ralexclark.ca:' + port + '/api');
});

mongoose.connect(config.database, {server : { poolSize:1 } } );

require('./config/passport')(passport);

var apiRoutes = express.Router();

//Register
apiRoutes.post('/register', function (req, res) {

  if (!req.body.user.email || !req.body.user.password)
    res.json({ success: false, msg: 'Please pass name and password.' });
  else
  {
    var newUser = new User({
      name: req.body.user.name,
      password: req.body.user.password,
      email: req.body.user.email,
      submitArticleFlag: true //THIS NEEDS TO BE REMOVED IN THE FUTURE.
    });

    newUser.save(function (err) {
      if (err) {
        return res.json({ success: false, msg: 'Username already exists.' });
      }

      res.json({ success: true, msg: 'Success created new user.' });
    });
  }
});

//Login
apiRoutes.post('/login', function (req, res) {
  User.findOne({ email: req.body.email }, function (err, user) {
    if (err) throw err;

    if (!user) {
      res.send({ success: false, msg: 'Authentication failed. User not found.' });
    }
    else {
      user.comparePassword(req.body.password, function (err, isMatch) {
        if (isMatch && !err) {
          //if user is found and password is right create a token
          var token = jwt.encode(user, config.secret);
          //return the information including token as json
          User.findOneAndUpdate({email: user.email}, { lastLogin: new Date() },function(err, user) {
            res.json({ success: true, token: 'JWT ' + token, user: user });
          });
          
        }
        else {
          res.send({ success: false, msg: 'Authenication failed. Wrong password.' });
        }
      });
    }
  });
});

apiRoutes.get('/getUser', passport.authenticate('jwt', { session: false }),
  function (req, res) {
    console.log(req.headers);
    var token = getToken(req.headers);
    if (token) {
      var decoded = jwt.decode(token, config.secret);
      console.log(decoded.email);
      User.findOne({ email: decoded.email }, function (err, user) {
        if (err) throw err;
        if (!user) return res.status(403).send({ success: false, msg: 'Authentication Failed. User not found.' });
        else res.json({ success: true, user: user});
      });
    }
    else res.status(403).send({ success: false, msg: 'No token provided.' });
  }
);

apiRoutes.post('/forget', function (req, res) {
  User.findOne({email: req.body.email }, function(err, user) {
    if(err) throw err;
    if(!user) res.json({success: false, msg:"Username is not found."});
    else {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        User.findOneAndUpdate({email:user.email}, {resetPasswordToken: token, resetPasswordExpires: Date.now() + 3600000}, function(err, user) {
          
          var mailOptions = {
            to: user.email,
            from: 'ralexclark@ralexclark.ca',
            subject: 'Node.js Password Reset',
            text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                  'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                  req.headers.referer + "/#/reset/" + token + '\n\n' +
                  'If you did not request this, please ignore this email and your password will remain unchanged.\n'
          };

          smtpTransport.sendMail(mailOptions, function(err) {
            if(err) throw err;
            else  res.json({ success:'true', msg: 'An e-mail has been sent to ' + user.email + ' with further instructions.' });
          });

        })
      });
    }
  });
});

apiRoutes.post('/reset', function(req, res) {
  User.findOne({resetPasswordToken: req.body.token, resetPasswordExpires: {$gt : Date.now( ) } }, function( err, user ) {
    if( !user ) res.json({success: false, msg: 'Password reset token is invalid or has expired.'})
    else {
      
      user.password = req.body.password;
      user.resetPasswordToken = '';
      user.resetPasswordExpires = '';

      user.save(function(err) {
        if(err) res.json({success: false, msg: 'Unable to update password.'});
        else res.json({success: true, msg: 'Password has been reset.'});
      })
    }
  });
});

apiRoutes.post('/submitArticle', function(req, res) {

    var token = getToken(req.headers);
    if (token) 
    {
      if(!req.body.article.title) res.json({success: false, msg: 'Article missing a title'});
      else if(!req.body.article.author) res.json({success: false, msg: 'Article missing an author'});
      else if(!req.body.article.updateDate) res.json({success: false, msg: 'Article missing a date'});
      else if(!req.body.article.text) res.json({success: false, msg: 'Article missing the article itself'});
      else {
        var newArticle = new Article({
          title: req.body.article.title,
          author: req.body.article.author,
          updateDate: req.body.article.updateDate,
          text: req.body.article.text
        });

        newArticle.save( function (err) {
          if(err) return res.json({ success: false, msg: 'Article failed to be inserted', err: err});

          res.json({ success: true, msg: 'Success created a new article'});
        });
      } 
    }
    else res.status(403).send({ success: false, msg: 'No token provided.' });
});

apiRoutes.get('/getArticles', function(req, res) {
  Article.find( {}, null, {sort: {updateDate: -1 }}, function(err, articles) {
    if(err) throw err;
    if(!articles) return res.status(403).send({success: false, msg: 'No articles found'});
    else res.json({success: true, articles: articles});
  })
});

//Private function to get token from headers.
getToken = function (headers) {
  if (headers && headers.authorization) {
    var parted = headers.authorization.split(' ');
    if (parted.length === 2) {
      return parted[1];
    }
    else return null;
  }
  else return null;
};

app.use('/api', apiRoutes);

var server = app.listen(port, function () {
  console.log('Express server listening on port ' + port);
});