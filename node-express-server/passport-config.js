let jwtOptions;

module.exports.buildJwtOptions = jwtFromRequest => {
  jwtOptions = {};
  jwtOptions.jwtFromRequest = jwtFromRequest;
  jwtOptions.secretOrKey = 'secret key bla bla';
  return jwtOptions;
};

module.exports.getJwtOptions = () => {
  return jwtOptions;
};
