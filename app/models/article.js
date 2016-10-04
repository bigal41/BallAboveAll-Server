var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt');

//Set up a mongoose model
var ArticleSchema = new Schema({
   title: {
      type: String,
      required: true
   },
   author: {
      type: String,
      required: true
   },
   authorUsername: {
      type: String,
      required: true,
   },
   updateDate: {
      type: Date,
      required: true
   },
   text: {
      type: String,
      required: true
   }
});

module.exports = mongoose.model('Article', ArticleSchema );