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

const _ = require('lodash');
const logger = require('../logger-winston');
const db = require('../db');
const jwt = require('jsonwebtoken');

const passportConfig = require('../passport-config');
const jwtOptions = passportConfig.getJwtOptions();

/**
 * @api {post} /api/login Login as local user.
 * @apiVersion 0.0.1
 * @apiName Login
 * @apiGroup Auth
 * @apiPermission none
 *
 * @apiDescription Login as local user.
 *
 * @apiParam {String} username User nickname
 * @apiParam {String} password User password.
 *
 * @apiHeaderExample {json} Header-Example:
 *     {
 *       "Content-Type": "application/json",
 *				"XSRF-TOKEN": "A VALID TOKEN"
 *     }
 *
 * @apiSuccess {String} token Text with the jwt token.
 *
 * @apiError ParamsError 400 All fields required.
 * @apiError NotAuthError 401 Incorrect username or password.
 * @apiError UserNotEnabledError 401 Incorrect username or password. Or this account is not activated, check your mailbox.
 *
 * @apiParamExample {json} Request-Example:
 *     {
 *       "username": "admin",
 *       "password": "admin"
 *     }
 *
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 200 OK
 *   {
 *     "token":"JWT TOKEN"
 *   }
 */
module.exports.login = (req, res) => {
  logger.debug('REST auth login - logging in');

  if (!req.body.username || !req.body.password) {
    res.status(400).json({ message: 'all fields required' });
    return;
  }

  const username = req.body.username;
  const password = req.body.password;

  // usually this would be a database call:
  const user = db.db[_.findIndex(db.db, o => o && o.credential && o.credential.username === username && o.credential.password === password)];
  if (!user || !user.credential) {
    res.status(401).json({ message: 'Incorrect username or password' });
    return;
  }

  console.log('user: ', user);

  if (user.credential.password === req.body.password) {
    // from now on we'll identify the user by the id and the id is the only personalized value that goes into our token
    let payload = { id: user.credential.id };
    console.log('payload', payload);
    const token = jwt.sign(getJwtToSign(payload), jwtOptions.secretOrKey);
    console.log('token', token);

    const indexLoggedUser = db.tokens.findIndex(o => o && (o.token === token || o.userId === user.credential.id));

    if (indexLoggedUser !== -1) {
      db.tokens.splice(indexLoggedUser, 1); // remove element
      db.tokens.push({ token: token, userId: user.credential.id });
    } else {
      db.tokens.push({ token: token, userId: user.credential.id });
    }
    // tokenMap.set(token, user.credential.id);

    console.log('db.tokens', db.tokens);

    res.status(200).json({ token: token });
  } else {
    res.status(401).json({ message: 'Incorrect username or password' });
  }
};

/**
 * @api {get} /api/logout Logout user.
 * @apiVersion 0.0.1
 * @apiName Logout
 * @apiGroup Auth
 * @apiPermission authenticate
 *
 * @apiDescription Logout.
 *
 * @apiSuccess {String} message Constant text 'Logout succeeded'.
 *
 * @apiHeaderExample {json} Header-Example:
 *     {
 *       "Content-Type": "application/json",
 *       "Authorization": "Bearer A_VALID_JWT_TOKEN"
 *			 "XSRF-TOKEN": "A VALID TOKEN"
 *     }
 *
 * @apiErrorExample {text} Error-Response:
 *   HTTP/1.1 401 ANAUTHORIZED
 *
 *   Unauthorized
 */
module.exports.logout = (req, res) => {
  console.log('req.headers.authorization is ', req.headers.authorization);
  console.log('req.user is ', req.user);

  const currentToken = req.headers.authorization.replace('Bearer ', '');
  const currentUser = req.user;
  db.tokens = db.tokens.filter(o => o && currentToken && currentUser && o.token !== currentToken && o.userId !== currentUser.id);

  console.log('db.tokens after logout', db.tokens);
  res.status(200).json({ message: 'Logout succeeded' });
};

function getJwtToSign(thisObject) {
  const expiry = new Date();
  expiry.setTime(expiry.getTime() + 600000); //valid for 10 minutes (10*60*1000)
  return {
    id: thisObject.id,
    exp: parseFloat(expiry.getTime())
  };
}
