'use strict';

const APIS = require('./apis');

const ctrlKeepAlive = require('../controllers/keepalive');
const ctrlSecret = require('../controllers/secret');
const ctrlAuth = require('../controllers/auth');

module.exports = function(express, passport) {
  let router = express.Router();

  // keep alive
  router.get(APIS.GET_KEEPALIVE, [ctrlKeepAlive.keepAlive]);

  //-----------------------------------------------------------------------------------------
  //-----------------------------------authentication----------------------------------------
  //-----------------------------------------------------------------------------------------
  //login
  router.post(APIS.POST_LOGIN, [ctrlAuth.login]);

  //secret
  router.get(APIS.GET_SECRET, [passport.authenticate('jwt', { session: true }), ctrlSecret.secret]);

  // logout
  router.get(APIS.GET_LOGOUT, [passport.authenticate('jwt', { session: true }), ctrlAuth.logout]);

  module.exports = router;
  return router;
};
