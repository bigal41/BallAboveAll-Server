var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt');

//Set up a mongoose model
var UserSchema = new Schema({
   email: {
      type: String,
      unique: true,
      required: true
   },
   password: {
      type: String,
      required: true
   },
   name: {
      type: String,
      required: true
   },
   lastLogin: Date,
   resetPasswordToken: String,
   resetPasswordExpires: Date,
   submitArticleFlag: Boolean
});

UserSchema.pre('save', function(next) {
   var user = this;
   if(this.isModified('password') || this.isNew) {
      bcrypt.genSalt(10, function(err, salt) {
         if(err) return next(err);
         bcrypt.hash(user.password, salt, function(err, hash) {
            if(err) return next(err);
            user.password = hash;
            next();
         });
      });
   }
   else return next();
});

UserSchema.methods.comparePassword = function( password, cb ) {
   bcrypt.compare(password, this.password, function(err, isMatch) {
      if(err) return cb(err);
      cb(null, isMatch);
   });
};

module.exports = mongoose.model('User', UserSchema);
