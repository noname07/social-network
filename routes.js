var express = require('express');
var passport = require('passport');
var User = require("./models/users");

var router = express.Router();

router.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  res.locals.errors = req.flash('error');
  res.locals.infos = req.flash('info');
  next();
});

router.get("/", function(req, res, next) {
  User.find().sort({ createdAt: 'descending' }).exec(function(err, users) {
    if (err)
      return next(err);
    res.render('index', { users: users });
  });
});
module.exports = router;

router.get('/signup', function(req, res) {
  res.render('signup');
});

router.post('/signup', function(req, res, next) {
  var username = req.body.username;
  var password = req.body.password;

  user.findOne({username: username}, function(err, user) {
    if(error) {
      return next(err);
    }
    if(user) {
      req.flash('error', 'user already exist');
      return res.redirect('/signup');
    }
    var newUser = new User({
      username: username,
      password: password
    });
    newUser.save(next);
  });
  },
  passport.authenticate('login', {
    successRedirect: '/',
    failureRedirect: '/signup',
    failureFlash: true
  })
);
