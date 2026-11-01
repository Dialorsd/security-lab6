const express = require('express');
const crypto = require('crypto');
const config = require('./config');

module.exports = function idp() {
  const r = express.Router();
  const codes = new Map();
  const accessTokens = new Map();
  const ACCOUNTS = [
    { sub: 'idp-1001', email: 'student@idp.example', name: 'Студент Іваненко' },
    { sub: 'idp-1002', email: 'teacher@idp.example', name: 'Викладач Петренко' },
  ];

  r.get('/authorize', (req, res) => {
    const { client_id, redirect_uri, state, response_type } = req.query;
    if (client_id !== config.oidc.clientId || response_type !== 'code' || !redirect_uri) return res.status(400).send('invalid_request');
    res.render('idp', { accounts: ACCOUNTS, q: { client_id, redirect_uri, state: state || '' } });
  });

  r.post('/authorize', express.urlencoded({ extended: false }), (req, res) => {
    const { sub, redirect_uri, state, client_id } = req.body;
    const user = ACCOUNTS.find((a) => a.sub === sub);
    if (!user || client_id !== config.oidc.clientId) return res.status(400).send('invalid_request');
    const code = crypto.randomBytes(16).toString('hex');
    codes.set(code, { user, redirect_uri, exp: Date.now() + 60_000 });
    const u = new URL(redirect_uri);
    u.searchParams.set('code', code);
    if (state) u.searchParams.set('state', state);
    res.redirect(u.toString());
  });

  r.post('/token', express.urlencoded({ extended: false }), (req, res) => {
    const { code, client_id, client_secret, redirect_uri } = req.body;
    const c = codes.get(code);
    codes.delete(code);
    if (!c || c.exp < Date.now() || client_id !== config.oidc.clientId || client_secret !== config.oidc.clientSecret || c.redirect_uri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    const at = crypto.randomBytes(24).toString('hex');
    accessTokens.set(at, c.user);
    res.json({ access_token: at, token_type: 'Bearer', expires_in: 300 });
  });

  r.get('/userinfo', (req, res) => {
    const at = (req.get('authorization') || '').replace(/^Bearer /, '');
    const u = accessTokens.get(at);
    if (!u) return res.status(401).json({ error: 'invalid_token' });
    res.json({ sub: u.sub, email: u.email, email_verified: true, name: u.name });
  });
  return r;
};
