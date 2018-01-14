let tokens = [];

let dbMock = [
  {
    somethingelse: 'bla bla',
    credential: {
      id: 1,
      username: 'admin',
      password: 'password'
    }
  },
  {
    somethingelse: 'bla bla',
    credential: {
      id: 2,
      username: 'admin',
      password: 'admin'
    }
  }
];

module.exports = {
  db: dbMock,
  tokens: tokens
};
