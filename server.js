var express = require('express');
var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');
var passport = require('passport');
var jwt = require('jwt-simple');
var nodemailer = require('nodemailer');
var async = require('async');
var crypto = require('crypto');
var http = require('http');
var https = require('https');
var fs = require('fs');

//Database config
var config = require('./config/database');

//MongoDB Schema
var User = require('./app/models/user');
var Article = require('./app/models/article');

//Define our express app
var app = express();

//Define a non secure app.
var nonSecureApp = express();

//Define the port our server will run on
var port = process.env.PORT || 8080;
//var port = 80;

//Define email transporter;
var smtpTransport = nodemailer.createTransport(config.smtpConfig);

//Get our request parameters
app.use(bodyParser.urlencoded({
   extended: false
}));
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
   } else {
      next();
   }
});

//Demo Route
app.get('/', function (req, res) {
   res.send('Hello! The app is at http://ballabove.ralexclark.ca:' + port + '/api');
});

nonSecureApp.get('/', function( req, res) {
   res.send('This connection is non secure! Please use our secure API which is located at https://ballabove.ralexclark.ca:' + port + '/api');
});

mongoose.connect(config.database, {
   server: {
      poolSize: 1
   }
});

require('./config/passport')(passport);

////////////////////////////////////////////////////////////
// Define Routes                                          //
////////////////////////////////////////////////////////////

//Define the express router
var apiRoutes = express.Router();

/**
 * Get Routes
 */

//Retrieve Articles
apiRoutes.get('/articles', function (req, res) {
   Article.find({}, null, {
      sort: {
         updateDate: -1
      }
   }, function (err, articles) {
      if (err) throw err;
      if (!articles) return res.status(403).send({
         success: false,
         msg: 'No articles found'
      });
      else res.json({
         success: true,
         articles: articles
      });
   })
});

//Get User
apiRoutes.get('/user', passport.authenticate('jwt', {
      session: false
   }),
   function (req, res) {
      
      var token = getToken(req.headers);
      if (token) {
         var decoded = jwt.decode(token, config.secret);
         User.findOne({
            username: decoded.username
         }, function (err, user) {
            if (err) throw err;
            if (!user) return res.status(403).send({
               success: false,
               msg: 'Authentication Failed. User not found.'
            });
            else res.json({
               success: true,
               user: user
            });
         });
      } else res.status(403).send({
         success: false,
         msg: 'No token provided.'
      });
   }
);

//Get a pending verification users
apiRoutes.get('/pendingVerification', function (req, res) {

   User.find({
      pendingVerification: true
   }, function (err, users) {
      if (err) throw err;
      else if (!users) res.json({
         success: false,
         msg: 'There were no users needed to be verified'
      });
      pendingVerification: true
   }, function (err, users) {
      if (err) throw err;
      else if (!users) res.json({
         success: false,
         msg: 'There were no users needed to be verified'
      });
      else res.json({
         success: true,
         users: users
      });
   });
});

//Get all pending approval articles
apiRoutes.get('/pendingApproval', function (req, res) {

   Article.find({ approved: false }, function (err, articles) {
      if (err) throw err;
      else if (!articles) res.json({ success: false, msg: 'There were no articles that needed be approved' });
      else res.json({ success: true, articles: articles });
   });

});

/**
 * Post Routes
 */

//Approve the article
apiRoutes.post('/approveArticle', function (req, res) {

   var token = getToken(req.headers);

   //We want to make sure we have a token
   if (token) {

      Article.findOneAndUpdate({
         title: req.body.article.title,
         authorUsername: req.body.article.authorUsername
      }, {
         approved: true
      }, function (err, article) {
         if (err) throw err;
         else if (!article) return res.status(403).send({
            success: false,
            msg: 'No Article was updated'
         });
         else {
            //NOTE: Do we mail the original author and let them know if their article has been approved?
            return res.json({
               success: true,
               msg: "Article has been approved"
            });
         }
      });
   } else res.status(403).send({
      success: false,
      msg: 'No token provided.'
   });
});

//Retireve article by ID
apiRoutes.post('/articleByID', function (req, res) {

   Article.findOne({
      _id: req.body.id
   }, function (err, article) {
      if (err) throw err;
      if (!article) return res.status(403).send({
         success: false,
         msg: 'No Article found'
      });
      else res.json({
         success: true,
         article: article
      });
   });

});

//Retrieve Articles by user
apiRoutes.post('/articlesByUser', function (req, res) {
   Article.find({
      authorUsername: req.body.username
   }, null, {
      sort: {
         updateDate: -1
      }
   }, function (err, articles) {
      if (err) throw err;
      if (!articles) return res.status(403).send({
         success: false,
         msg: 'No articles found'
      });
      else res.json({
         success: true,
         articles: articles
      });
   })
});

//Forgot Password
apiRoutes.post('/forget', function (req, res) {
   User.findOne({
      email: req.body.email
   }, function (err, user) {
      if (err) throw err;
      if (!user) res.json({
         success: false,
         msg: "User was not found with this email."
      });
      else {
         crypto.randomBytes(20, function (err, buf) {
            var token = buf.toString('hex');
            User.findOneAndUpdate({
               username: user.username
            }, {
               resetPasswordToken: token,
               resetPasswordExpires: Date.now() + 3600000
            }, function (err, user) {

               var mailOptions = {
                  to: user.email,
                  from: 'ralexclark@ralexclark.ca',
                  subject: 'Node.js Password Reset',
                  text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                     'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                     req.headers.referer + "/#/reset/" + token + '\n\n' +
                     'If you did not request this, please ignore this email and your password will remain unchanged.\n'
               };

               smtpTransport.sendMail(mailOptions, function (err) {
                  if (err) throw err;
                  else res.json({
                     success: 'true',
                     msg: 'An e-mail has been sent to ' + user.email + ' with further instructions.'
                  });
               });

            })
         });
      }
   });
});

//Login
apiRoutes.post('/login', function (req, res) {
   User.findOne({
      username: req.body.username
   }, function (err, user) {
      if (err) throw err;

      if (!user) {
         res.send({
            success: false,
            msg: 'Authentication failed. User not found.'
         });
      } else {
         user.comparePassword(req.body.password, function (err, isMatch) {
            if (isMatch && !err) {
               //if user is found and password is right create a token
               var token = jwt.encode(user, config.secret);
               //return the information including token as json
               User.findOneAndUpdate({
                  username: user.username
               }, {
                  lastLogin: new Date()
               }, function (err, user) {
                  res.json({
                     success: true,
                     token: 'JWT ' + token,
                     user: user
                  });
               });

            } else {
               res.send({
                  success: false,
                  msg: 'Authenication failed. Wrong password.'
               });
            }
         });
      }
   });
});

//Get profile for a user
apiRoutes.post('/profileByUser', function (req, res) {

   User.findOne({
      username: req.body.username
   }, function (err, user) {
      if (err) throw err;
      else if (!user) res.json({
         success: false,
         msg: 'No user with this username'
      });
      else res.json({
         success: true,
         user: {
            name: user.name,
            email: user.email,
            username: user.username,
            verified: user.verified
         }
      });
   });
});

//Register
apiRoutes.post('/register', function (req, res) {

   if (!req.body.user.email || !req.body.user.password)
      res.json({
         success: false,
         msg: 'Please pass name and password.'
      });
   else {
      var newUser = new User({
         username: req.body.user.username,
         name: req.body.user.name,
         password: req.body.user.password,
         email: req.body.user.email,
         verified: false, //THIS NEEDS TO BE REMOVED IN THE FUTURE.
         pendingVerification: false,
         administrator: false
      });

      newUser.save(function (err) {
         if (err) {
            return res.json({
               success: false,
               msg: 'Username already exists.'
            });
         }

         res.json({
            success: true,
            msg: 'Success created new user.'
         });
      });
   }
});

//Reset Password
apiRoutes.post('/reset', function (req, res) {
   User.findOne({
      resetPasswordToken: req.body.token,
      resetPasswordExpires: {
         $gt: Date.now()
      }
   }, function (err, user) {
      if (!user) res.json({
         success: false,
         msg: 'Password reset token is invalid or has expired.'
      })
      else {

         user.password = req.body.password;
         user.resetPasswordToken = '';
         user.resetPasswordExpires = '';

         user.save(function (err) {
            if (err) res.json({
               success: false,
               msg: 'Unable to update password.'
            });
            else res.json({
               success: true,
               msg: 'Password has been reset.'
            });
         })
      }
   });
});

//Submit an Article
apiRoutes.post('/submitArticle', function (req, res) {

   var token = getToken(req.headers);
   if (token) {
      if (!req.body.article.title) res.json({
         success: false,
         msg: 'Article missing a title'
      });
      else if (!req.body.user.name) res.json({
         success: false,
         msg: 'Article missing an author'
      });
      else if (!req.body.user.username) res.json({
         success: false,
         msg: 'Article missing an username'
      });
      else if (!req.body.article.updateDate) res.json({
         success: false,
         msg: 'Article missing a date'
      });
      else if (!req.body.article.text) res.json({
         success: false,
         msg: 'Article missing the article itself'
      });
      else {
         var newArticle = new Article({
            title: req.body.article.title,
            author: req.body.user.name,
            authorUsername: req.body.user.username,
            updateDate: req.body.article.updateDate,
            text: req.body.article.text,
            approved: false
         });

         newArticle.save(function (err) {
            if (err) return res.json({
               success: false,
               msg: 'Article failed to be inserted',
               err: err
            });

            res.json({
               success: true,
               msg: 'Success created a new article'
            });
         });
      }
   } else res.status(403).send({
      success: false,
      msg: 'No token provided.'
   });
});

//Verify a User
apiRoutes.post('/verifyUser', function (req, res) {

   var token = getToken(req.headers);

   //We want to make sure we have a token
   if (token) {

      User.findOneAndUpdate({
         username: req.body.user.username
      }, {
         verified: true,
         pendingVerification: false
      }, function (err, user) {

         if (err) throw err;
         else if (!user) return res.status(403).send({
            success: false,
            msg: 'No User was updated'
         });
         else {

            var mailOptions = {
               to: user.email,
               from: 'ralexclark@ralexclark.ca',
               subject: 'You have have been verified',
               text: 'Hello ' + user.name + '\n\n' +
                  'We have reviewed your application to be a verified author.\n\n' +
                  'Ball Above All Staff'
            };

            smtpTransport.sendMail(mailOptions, function (err) {
               if (err) throw err;
               else res.json({
                  success: true,
                  msg: user.name + ' has been verified. We have let them know.'
               });
            });

         }
      });
   } else res.status(403).send({
      success: false,
      msg: 'No token provided.'
   });
});

//Private function to get token from headers.
getToken = function (headers) {
   if (headers && headers.authorization) {
      var parted = headers.authorization.split(' ');
      if (parted.length === 2) {
         return parted[1];
      } else return null;
   } else return null;
};

app.use('/api', apiRoutes);

//var server = app.listen(port, function () {
//   console.log('Express server listening on port ' + port);
//});

//http.createServer(app).listen(port, function() {
//   console.log('Express server listening on port ' + port);
//});

var sslOptions = {
   key: fs.readFileSync('./tls/key.pem'),
   cert: fs.readFileSync('./tls/cert.pem')
};

http.createServer( nonSecureApp ).listen(8181, function() {
   console.log('Express server listening on port ' + 8181);
});

https.createServer( sslOptions, app ).listen( 8080, function(){
   console.log('Secure express server listening on port ' + 8080);
});

