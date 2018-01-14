'use strict';

const _ = require('lodash');
let logger = require('../logger-winston');

/**
 * @api {post} /api/secret Get a secret message
 * @apiVersion 0.0.1
 * @apiName GetSecret
 * @apiGroup Secret
 * @apiPermission authentication
 *
 * @apiDescription Get a secret message.
 *
 * @apiHeaderExample {json} Header-Example:
 *     {
 *       "Content-Type": "application/json",
 *       "Authorization": "Bearer A_VALID_JWT_TOKEN"
 *			 "XSRF-TOKEN": "A VALID TOKEN"
 *     }
 *
 * @apiSuccess {String} message Constant a secret message
 *
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 200 OK
 *   {
 *     "message": "This is a secret message from an authenticated rest API"
 *   }
 */
module.exports.secret = function(req, res) {
  logger.debug('REST secret called');
  res.status(200).json({ message: 'This is a secret message from an authenticated rest API' });
};
