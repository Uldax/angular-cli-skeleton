/*
 * MIT License
 *
 * Copyright (c) 2017-2018 Stefano Cappa
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

'use strict';

const redis = require('redis');
// const ratelimit = require('ratelimit');

const APIS = require('./apis');

const ctrlKeepAlive = require('../controllers/keepalive');
const ctrlSecret = require('../controllers/secret');
const ctrlAuth = require('../controllers/auth');

module.exports = (express, passport) => {
  const router = express.Router();

  //-----------------------------------------------------------------------------------------
  //----------------------------------------public-------------------------------------------
  //-----------------------------------------------------------------------------------------

  // keep alive
  router.get(APIS.GET_KEEPALIVE, [ctrlKeepAlive.keepAlive]);

  //login

  // const userBasedRatelimit = ratelimit({
  //   db: redis.createClient(),
  //   duration: 60000,
  //   max: 10,
  //   id: context => context.body.username
  // });
  //
  // const ipBasedRatelimit = ratelimit({
  //   db: redis.createClient(),
  //   duration: 60000,
  //   max: 10,
  //   id: context => context.ip
  // });


  router.post(APIS.POST_LOGIN, [ctrlAuth.login]);

  //-----------------------------------------------------------------------------------------
  //------------------------------------authenticated----------------------------------------
  //-----------------------------------------------------------------------------------------

  //secret
  router.get(APIS.GET_SECRET, [passport.authenticate('jwt', {session: true}), ctrlSecret.secret]);

  // logout
  router.get(APIS.GET_LOGOUT, [passport.authenticate('jwt', {session: true}), ctrlAuth.logout]);

  module.exports = router;
  return router;
};
