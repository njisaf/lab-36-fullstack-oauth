'use strict'

const Router = require('express').Router
const createError = require('http-errors')
const jsonParser = require('body-parser').json()
const debug = require('debug')('slugram:auth-router')
const basicAuth = require('../lib/basic-auth-middleware.js')
const User = require('../model/user.js')

// module constants
const authRouter = module.exports = Router()

authRouter.post('/api/signup', jsonParser, function(req, res, next){
  debug('POST /api/signup')

  let password = req.body.password
  delete req.body.password
  let user = new User(req.body)

  // checkfor password before running generatePasswordHash
  if (!password)
    return next(createError(400, 'requires password'))
  if (password.length < 8)
    return next(createError(400, 'password must be 8 characters'))

  user.generatePasswordHash(password)
  .then( user => user.save()) // check for unique username with mongoose unique
  .then( user => user.generateToken())
  .then( token => res.send(token))
  .catch(next)
})

authRouter.get('/api/login', basicAuth, function(req, res, next){
  debug('GET /api/login')

  User.findOne({username: req.auth.username})
  .then( user => user.comparePasswordHash(req.auth.password))
  .catch(err => Promise.reject(createError(401, err.message)))
  .then( user => user.generateToken())
  .then( token => res.send(token))
  .catch(next)
})

authRouter.get('/api/auth/oauth_callback', googleOAuth, function(req, res) {
  debug('GET /api/auth/oauth_callback');

  if (req.googleError) {
    return res.redirect('/?error=access_denied');
  }

  User.findOne({email: req.googleOAuth.email})
  .then(user => {
    if (!user) return Promise.reject(new Error('User not found!'));
    return user;
  })
  .catch(err => {
    if (err.message === 'User not found!') {
      let newUser = {
        username: req.googleOAuth.email,
        email: req.googleOAuth.email,
        google: {
          googleID: req.googleOAuth.googleID,
          tokenTTL: req.googleOAuth.tokenTTL,
          tokenTimeStamp: Date.now(),
          refreshToken: req.googleOAuth.refreshToken,
          accessToken: req.googleOAuth.accessToken,
        },
      };

      return new User(newUser).save();
    }
    return Promise.reject(err);
  })
  .then(user => user.generateToken())
  .then(token => {
    res.redirect(`/?token=${token}`);
  })
  .catch(err => {
    console.error(err.message);
    debug('User not found!');
    res.redirect('/');
  })
});
