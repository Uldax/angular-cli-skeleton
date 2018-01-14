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

// You cannot use config.js here!!!

let winston = require('winston');
winston.emitErrs = true;

function getFormatter(options) {
  // Return string will be passed to logger.
  return (
    options.timestamp() +
    ' ' +
    options.level.toUpperCase() +
    ' ' +
    (undefined !== options.message ? options.message : '') +
    (options.meta && Object.keys(options.meta).length ? '\n\t' + JSON.stringify(options.meta) : '')
  );
}

let logger = new winston.Logger({
  transports: [
    new winston.transports.File({
      level: process.env.NODE_ENV === 'production' ? 'error' : 'debug',
      filename: 'server.log',
      handleExceptions: true,
      json: false,
      //maxsize: 5242880, //5MB
      //maxFiles: 5,
      colorize: false,
      timestamp: () => Date.now(),
      formatter: options => getFormatter(options)
    }),
    new winston.transports.Console({
      level: 'debug',
      handleExceptions: true,
      json: false,
      colorize: true,
      timestamp: () => Date.now(),
      formatter: options => getFormatter(options)
    })
  ],
  exitOnError: false
});

module.exports = logger;

module.exports.stream = {
  write: message => {
    logger.info(message);
  }
};
