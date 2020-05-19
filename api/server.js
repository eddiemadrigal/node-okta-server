const express = require('express');
const OktaJwtVerifier = require('@okta/jwt-verifier');
let cors = require('cors');

const server = express();
server.use(cors());

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: `https://${process.env.DOMAIN}/oauth2/default`,
  clientId: process.env.CLIENTID,
  assertClaims: {
    aud: 'api://default',
  }
}); 

// public route
server.get('/api/publicInfo', (req, res) => {
  res.status(200).json({ data: 'You are viewing public info' });
});

// protected route
server.get('/api/profile', verifyToken, (req, res) => {
  // res.json(req.jwt); // show token if validated successfully
  res.status(200).json({ data: 'Messages: Authorized users only!' });
});

// protected route
server.get('/api/messages', verifyToken, (req, res) => {
  // res.json(req.jwt); // show token if validated successfully
  res.status(200).json({ data: 'Message: Authorized users only!' });
});

function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'] || '';
  const match = bearerHeader.match(/Bearer (.+)/);

  if (!match) {
    return res.status(401).end();
  }

  const accessToken = match[1];
  const expectedAudience = 'api://default';

  return oktaJwtVerifier.verifyAccessToken(accessToken, expectedAudience)
    .then((jwt) => {
      req.jwt = jwt;
      next();
    })
    .catch( err => {
      res.status(401).send(err.message);
    })
}

module.exports = server;