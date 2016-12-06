var bcrypt = require('bcrypt-nodejs');
var SALT_FACTOR = 10; //Bigger will be more secure but slower. 4 to 32 is the valid range.
var mongoose = require('mongoose');
var userSchema = mongoose.Schema({
    username: {type: String, required: true, unique: true},
    password: {type: String, required: true, minlenght: 8},
    createAt: {type: Date, default: Date.now()},
    displayedName: String,
    bio: String
});

userSchema.methods.name = function() {
  return this.displayedName || this.username;
};

var noop = function() {}; //Do nothing function for bcrypt.hash

userSchema.pre('save', function(done) {
  var user = this;
  if(!user.isModified('password')) {
    return done();
  }
  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if(err) {
      return done(error);
    }
    bcrypt.hash(user.password, salt, noop, function(err, hashedPassword) {
      user.password = hashedPassword;
      done();
      });
    });
});

userSchema.methods.checkPassword = function (guess, done) {
  bcrypt.compare(guess, this.password, function(err, isMatch) {
    done(err, isMatch);
  });
};

var User = mongoose.model("User", userSchema);
module.exports = User;
