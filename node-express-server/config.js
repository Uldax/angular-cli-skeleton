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

let logger = require('./logger-winston.js');

const useDotenv = process.env.CI !== 'yes' && process.env.CI !== true;

logger.warn(`Using dotenv condition is: ${useDotenv}`);

if (useDotenv === true) {
  logger.warn('Initializing dotenv (requires .env file)');
  let dotenvPath = null;
  switch (process.env.NODE_ENV) {
    case 'production':
      dotenvPath = '.env_prod';
      break;
    case 'e2e':
      dotenvPath = '.env_e2e';
      break;
    default:
    case 'development':
      dotenvPath = '.env';
      break;
  }

  const dotenv = require('dotenv').config({path: dotenvPath});
  if (dotenv.error) {
    throw dotenv.error;
  }
  logger.debug(`dotenv ${process.env.NODE_ENV}`, dotenv.parsed);
}

module.exports = {
  isCI: () => process.env.CI === 'yes' || process.env.CI === true,
  isProd: () => process.env.NODE_ENV === 'production',
  isTest: () => process.env.NODE_ENV === 'test',

  // used to run this server as back-end for inntegration testing on client-side
  // this method isn't used for integration testing on server-side
  isForE2eTest: () => process.env.NODE_ENV === 'e2e',

  NODE_ENV: process.env.NODE_ENV || 'development',
  CI: process.env.CI || 'yes',
  PORT: process.env.PORT || 3000,
  JWT_SECRET: process.env.JWT_SECRET || 'secret key',

  // re-assign all process.env variables to be used in this app and defined with dotenv to constants
  // In this way I can see all variables defined with donenv and used in this app
  // In CI I can't use dotenv => I provide default values for all these constants
  FRONT_END_PATH: process.env.FRONT_END_PATH || '../dist/browser',
  LARGE_PAYLOAD_MESSAGE: process.env.LARGE_PAYLOAD_MESSAGE || 'stop it!',
  EXPRESS_SESSION_SECRET: process.env.EXPRESS_SESSION_SECRET || 'keyboard cat',
  HELMET_HIDE_POWERED_BY: process.env.HELMET_HIDE_POWERED_BY || 'f__k u idiot',
  HELMET_REFERRER_POLICY: process.env.HELMET_REFERRER_POLICY || 'no-referrer',
  HELMET_HPKP_SHA256S_1: process.env.HELMET_HPKP_SHA256S_1 || 'AbCdEf123=',
  HELMET_HPKP_SHA256S_2: process.env.HELMET_HPKP_SHA256S_2 || 'ZyXwVu456=',
  HELMET_HPKP_REPORT_URI: process.env.HELMET_HPKP_REPORT_URI || 'https://example.com/hpkp-report',
  HELMET_EXPECT_CT_REPORT_URI: process.env.HELMET_EXPECT_CT_REPORT_URI || 'https://example.com/expect-ct-report',

  RATELIMITER_WINDOW_MS: process.env.RATELIMITER_WINDOW_MS || (15 * 60 * 1000),   // by default 15 minutes
  RATELIMITER_MAX: process.env.RATELIMITER_MAX || 50,
  RATELIMITER_DELAY_AFTER: process.env.RATELIMITER_DELAY_AFTER || 5,
  RATELIMITER_DELAY_MS: process.env.RATELIMITER_DELAY_MS || (3 * 1000), // by default 3 seconds
  RATELIMITER_MESSAGE: process.env.RATELIMITER_MESSAGE || 'Too many requests from this IP, please try again after 15 minutes',

};
