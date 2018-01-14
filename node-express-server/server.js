'use strict';

// --------------------------------------------------------
// ------------------Init env variables--------------------
// --------------------------------------------------------
const config = require('./config');
if (process.env.NODE_ENV !== 'production') {
  console.log('config file loaded', config);
}
// --------------------------------------------------------
// --------------------------------------------------------
// --------------------------------------------------------

let logger = require('./logger-winston.js');
logger.warn(`Starting with NODE_ENV=${config.NODE_ENV}`);
logger.warn(`config.CI is ${config.CI} and isCI is ${config.isCI()}`);

const APIS = require('./routes/apis');

let _ = require('lodash');
let express = require('express');
let bodyParser = require('body-parser');
// var redis = require('redis'); // TODO
// var ratelimit = require('ratelimit'); // TODO
let compression = require('compression');

let Utils = require('./util');
let db = require('./db');
let path = require('path');
let app = express();

let morgan = require('morgan');
let bluebird = require('bluebird');

// --------------------------------------------------------
// -----------------------Redis init-----------------------
// --------------------------------------------------------
// Init REDIS (below I add also redis to express session thanks to connect-redis)
// let redis = require('redis');
// let client = redis.createClient();
// let RedisStore = require('connect-redis')(session);
// let redisStore = bluebird.promisifyAll(new RedisStore({host: config.REDIS_HOST, port: config.REDIS_PORT, client: client, ttl: config.REDIS_TTL}));
// --------------------------------------------------------
// --------------------------------------------------------
// --------------------------------------------------------

// --------------------------------------------------------
// --------------------------------------------------------
// See this issue here https://github.com/Ks89/My-MEAN-website/issues/30
//  to understand this piece of code.
let pathFrontEndFolder, pathFrontEndIndex;
if ((config.isCI() || config.isTest()) && !config.isForE2eTest()) {
  console.log(`Executed in CI or TEST - providing fake '../My-MEAN-website-client' and index.html`);
  //provides fake directories and files to be able to run this files
  //also with mocha in both test and ci environments.
  //Otherwise, you are forced to run `npm run build` into ../My-MEAN-website-client's folder
  pathFrontEndFolder = path.join(__dirname);
  pathFrontEndIndex = path.join(__dirname, 'server.js');
} else {
  if (config.isProd()) {
    logger.warn('Providing both index.html and admin.html in a production environment');
    // you can add custom configuration here for production mode
  } else {
    logger.warn(`Providing real ${config.FRONT_END_PATH}, index.html and admin.html`);
  }
  pathFrontEndFolder = path.join(__dirname, config.FRONT_END_PATH);
  pathFrontEndIndex = path.join(__dirname, config.FRONT_END_PATH, 'index.html');
}
// --------------------------------------------------------
// --------------------------------------------------------

// --------------------------------------------------------------------------
// ----------------------------security packages-----------------------------
// --------------------------------------------------------------------------
// All security features are prefixed with `--SEC--`
// --SEC-- - github helmetjs/expect-ct [NOT helmet]
//    The Expect-CT HTTP header tells browsers to expect Certificate Transparency
let expectCt = require('expect-ct');
// --SEC-- - github analog-nico/hpp [NOT helmet]
//    [http params pollution] security package to prevent http params pollution
let hpp = require('hpp');
// --SEC-- - [CSRF] github.com/expressjs/csurf [NOT helmet]
let csrf = require('csurf');
// --SEC-- - authentication with JWT
let passport = require('passport');

let passportJWT = require('passport-jwt');
let ExtractJwt = passportJWT.ExtractJwt;
let JwtStrategy = passportJWT.Strategy;

let passportConfig = require('./passport-config');

let jwtOptions = passportConfig.buildJwtOptions(ExtractJwt.fromAuthHeaderAsBearerToken());
// jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
// jwtOptions.secretOrKey = 'secret key bla bla';

passport.use(
  new JwtStrategy(jwtOptions, function(jwt_payload, done) {
    console.log('payload received', jwt_payload);

    if (!jwt_payload) {
      console.error('jwt payload not valid');
      done(null, false);
    }

    console.log('jwt_payload is', jwt_payload);

    let isLoggedIn = db.tokens.findIndex(o => o && o.userId === jwt_payload.id) !== -1;
    console.log('jwtStrategy verify with isLoggedIn: ', isLoggedIn);

    if (!isLoggedIn) {
      console.error('cannot find previous login in tokenMap with payload', jwt_payload);
      return done(null, false);
    }

    // if (!tokenMap.has(jwt_payload.id)) {
    //   console.error(`cannot find user with id=${jwt_payload.id} in tokenMap`);
    //   done(null, false);
    // } else {
    //   let jwtFromMap = tokenMap.get(jwt_payload.id);
    // }

    try {
      let isJwtValidDate = Utils.isJwtValidDate(jwt_payload);
      console.log('isJwtValidDate', isJwtValidDate);

      if (!isJwtValidDate) {
        console.error('jwt has an invalid data');
        done(null, false);
      }

      console.log('systemDate valid');

      let user = db.db[_.findIndex(db.db, o => o && o.credential && o.credential.id === jwt_payload.id)];
      console.log(' user obtained from payload ', user);
      if (user && user.credential) {
        done(null, user.credential);
      } else {
        done(null, false);
      }
    } catch (err2) {
      console.error('exception thrown by isJwtValidDate', err2);
      done(null, false);
    }
  })
);
// jwtOptions.issuer = 'accounts.examplesoft.com';
// jwtOptions.audience = 'yoursite.net';
//
// --SEC-- - github ericmdantas/express-content-length-validator [NOT helmet]
//    large payload attacks - Make sure this application is
//    not vulnerable to large payload attacks
let contentLength = require('express-content-length-validator');
const MAX_CONTENT_LENGTH_ACCEPTED = 9999; // constants used with `contentLength`
// --SEC-- - Helmet
let helmet = require('helmet');
// --------------------------------------------------------------------------
// --------------------------------------------------------------------------

logger.warn('Initializing helmet');
// --SEC-- - [helmet] enable helmet
// this automatically add 9 of 11 security features
/*
 -dnsPrefetchControl controls browser DNS prefetching
 -frameguard to prevent clickjacking
 -hidePoweredBy to remove the X-Powered-By header
 -hpkp for HTTP Public Key Pinning
 -hsts for HTTP Strict Transport Security
 -ieNoOpen sets X-Download-Options for IE8+
 -noSniff to keep clients from sniffing the MIME type
 -xssFilter adds some small XSS protections
 */
// The other features NOT included by default are:
/*
 -contentSecurityPolicy for setting Content Security Policy
 -noCache to disable client-side caching => I don't want this for better performances
 -referrerPolicy to hide the Referer header
 */
app.use(helmet());

// --SEC-- - hidePoweredBy: X-Powered-By forced to a fake value to
// hide the default 'express' value [helmet]
app.use(helmet.hidePoweredBy({ setTo: config.HELMET_HIDE_POWERED_BY }));

// --SEC-- - noCache to disable client-side caching [helmet]
// I don't want this for better performances (leave commented :))
app.use(helmet.noCache());

// --SEC-- - referrer-policy to hide the Referer header [helmet]
app.use(helmet.referrerPolicy({ policy: config.HELMET_REFERRER_POLICY }));

// --SEC-- - Public Key Pinning (hpkp): HTTPS certificates can be forged,
//    allowing man-in-the middle attacks.
//    HTTP Public Key Pinning aims to help that. [helmet]
const ninetyDaysInSeconds = 7776000;
app.use(
  helmet.hpkp({
    maxAge: ninetyDaysInSeconds,
    sha256s: [config.HELMET_HPKP_SHA256S_1, config.HELMET_HPKP_SHA256S_2],
    includeSubdomains: true, // optional
    reportUri: config.HELMET_HPKP_REPORT_URI, // optional
    reportOnly: false, // optional
    // Set the header based on a condition.
    setIf: req => req.secure //optional ()
  })
);

// --SEC-- - Content Security Policy (CSP): Trying to prevent Injecting anything
//    unintended into our page. That could cause XSS vulnerabilities,
//    unintended tracking, malicious frames, and more. [helmet]
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: [`'self'`, 'localhost:3000', 'localhost:3001'],
      scriptSrc: [`'self'`, `'unsafe-inline'`, `'unsafe-eval'`],
      styleSrc: [`'self'`, `'unsafe-inline'`],
      fontSrc: [`'self'`],
      imgSrc: [`'self'`, 'localhost:3000', 'localhost:3001'],
      sandbox: ['allow-forms', 'allow-scripts', 'allow-same-origin', 'allow-popups'],
      frameSrc: [`'self'`], //frame-src is deprecated
      childSrc: [`'self'`],
      connectSrc: [`'self'`, 'ws://localhost:3000', 'ws://localhost:3001', 'ws://localhost:3100', 'ws://localhost:3300'],
      reportUri: '/report-violation',
      objectSrc: [`'none'`]
    },
    // Set to true if you only want browsers to report errors, not block them
    reportOnly: false,
    // Set to true if you want to blindly set all headers: Content-Security-Policy,
    // X-WebKit-CSP, and X-Content-Security-Policy.
    setAllHeaders: false,
    // Set to true if you want to disable CSP on Android where it can be buggy.
    disableAndroid: false,
    // Set to false if you want to completely disable any user-agent sniffing.
    // This may make the headers less compatible but it will be much faster.
    // This defaults to 'true'.
    browserSniff: true
  })
);

// --SEC-- - large payload attacks:
//   this line enables the middleware for all routes [NOT helmet]
app.use(
  contentLength.validateMax({
    max: MAX_CONTENT_LENGTH_ACCEPTED,
    status: 400,
    message: config.LARGE_PAYLOAD_MESSAGE
  })
); // max size accepted for the content-length

// --SEC-- - expect-ct
//  https://scotthelme.co.uk/a-new-security-header-expect-ct/
app.use(
  expectCt({
    enforce: true,
    maxAge: 30,
    reportUri: config.HELMET_EXPECT_CT_REPORT_URI
  })
);

logger.warn(`Initializing morgan (logger of req, res and so on... It's different from winston logger)`);
if (!config.isCI() && !config.isTest()) {
  // Disable morgan while testing to prevent very big log with useless information
  app.use(morgan('combined', { stream: logger.stream }));
}

console.log('pathFrontEndFolder', pathFrontEndFolder);

logger.warn('Initializing static resources');
app.use(express.static(pathFrontEndFolder));

logger.warn('Initializing bodyparser');

// parse application/x-www-form-urlencoded
// for easier testing with Postman or plain HTML forms
app.use(bodyParser.urlencoded({ extended: true }));
// parse application/json
app.use(bodyParser.json());

logger.warn('Initializing hpp');
// --SEC-- - http params pollution: activate http parameters pollution
// use this ALWAYS AFTER app.use(bodyParser.urlencoded()) [NOT helmet]
app.use(hpp());

logger.warn('Initializing passportjs');

passport.serializeUser(function(user, done) {
  console.log('serializing user', user);
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  console.log('deserializing user ', user);
  done(null, user);
});

app.use(passport.initialize());
app.use(passport.session());

// compress all requests using gzip
app.use(compression());

logger.warn('Initializing REST apis and CSRF');

// --------------------------------------- ROUTES ---------------------------------------
// enable middleware CSRF by csurf package [NOT helmet]
// before app.use(APIS.BASE_API_PATH, routesApi); to protect their,
// but after session and/or cookie initialization
// app.use(csrf());
// app.use(function (req, res, next) {
//   res.cookie('XSRF-TOKEN', req.csrfToken());
//   res.locals.csrftoken = req.csrfToken();
//   next();
// });

// APIs for all route protected with CSRF (all routes except for angular log's service)
let routesApi = require('./routes/index')(express, passport);
app.use(APIS.BASE_API_PATH, routesApi);
// --------------------------------------------------------------------------------------

logger.warn('Initializing static path for both index.html and admin.html');

// catch bad csrf token
app.use(function(err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') {
    return next(err);
  }
  // handle CSRF token errors here
  res.status(403).json({ message: 'session has expired or form tampered with' });
});

// catch 404 and forward to error handler
// app.use(function (req, res, next) {
//   let err = new Error('Not Found');
//   err.status = 404;
//   next(err);
// });

// error handlers
// Catch unauthorised errors
// app.use(function (err, req, res) {
//   if (err.name === 'UnauthorizedError') {
//     res.status(401);
//     res.json({ message: `${err.name}: ${err.message}`});
//   }
// });
//
// // development error handler
// // will print stacktrace
// if (app.get('env') === 'development') {
//   app.use(function (err, req, res) {
//     res.status(err.status || 500);
//     res.render('error', {
//       message: err.message,
//       error: err
//     });
//   });
// }

// production error handler
// no stacktraces leaked to user
// app.use(function (err, req, res) {
//   res.status(err.status || 500);
//   res.render('error', {
//     message: err.message,
//     error: {}
//   });
// });

// app.get('/api/keepalive', function(req, res) {
//   console.log('inside keepaline');
//   res.json({ message: 'Express is up!' });
//   // res.status(200).success();
// });
//
// app.post('/api/login', function(req, res) {
//   console.log('post', req.body);
//   let username = req.body.username;
//   let password = req.body.password;
//   // usually this would be a database call:
//   let user = db.db[_.findIndex(db.db, o => o && o.credential && o.credential.username === username && o.credential.password === password)];
//   if (!user || !user.credential) {
//     res.status(401).json({ message: 'no such user found' });
//     return;
//   }
//
//   console.log('user: ', user);
//
//   if (user.credential.password === req.body.password) {
//     // from now on we'll identify the user by the id and the id is the only personalized value that goes into our token
//     let payload = { id: user.credential.id };
//     console.log('payload', payload);
//     let token = jwt.sign(getJwtToSign(payload), jwtOptions.secretOrKey);
//     console.log('token', token);
//
//     let indexLoggedUser = db.tokens.findIndex(o => o && (o.token === token || o.userId === user.credential.id));
//
//     if (indexLoggedUser !== -1) {
//       db.tokens.splice(indexLoggedUser, 1); // remove element
//       db.tokens.push({ token: token, userId: user.credential.id });
//     } else {
//       db.tokens.push({ token: token, userId: user.credential.id });
//     }
//     // tokenMap.set(token, user.credential.id);
//
//     console.log('db.tokens', db.tokens);
//
//     res.status(200).json({ token: token });
//   } else {
//     res.status(401).json({ message: 'passwords did not match' });
//   }
// });
// app.get('/api/secret', passport.authenticate('jwt', { session: false }), function(req, res) {
//   // console.log(req.get('Authorization')); // to debug authentication data
//   res.json({ message: 'This is a secret message from an authenticated rest API' });
// });
//
// app.get('/api/logout', passport.authenticate('jwt', { session: false }), function(req, res) {
//   console.log('req.headers.authorization is ', req.headers.authorization);
//   console.log('req.user is ', req.user);
//
//   let currentToken = req.headers.authorization.replace('Bearer ', '');
//   let currentUser = req.user;
//   db.tokens = db.tokens.filter(o => o && currentToken && currentUser && o.token !== currentToken && o.userId !== currentUser.id);
//
//   console.log('db.tokens after logout', db.tokens);
//   res.status(200).json({ message: 'Logged out' });
// });

app.listen(3000, function() {
  console.log('Express running');
});
