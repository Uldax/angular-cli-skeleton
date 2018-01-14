'use strict';

let logger = require('../logger-winston');

/**
 * @api {get} /api/keepalive get keepalive
 * @apiVersion 0.0.1
 * @apiName GetKeepalive
 * @apiGroup Keepalive
 * @apiPermission none
 *
 * @apiDescription Check if server is up and running.
 *
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 200 OK
 *   {
 *     "message": "Express is up!"
 *   }
 */
module.exports.keepAlive = function(req, res) {
  logger.debug('REST keepAlive');
  console.log('inside keepalive');
  res.json({ message: 'Server is up and running!' });
};
