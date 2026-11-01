require('dotenv').config({ quiet: true });
const crypto = require('crypto');
const path = require('path');
const port = Number(process.env.PORT) || 3000;
module.exports = {
  port,
  baseUrl: process.env.BASE_URL || `http://localhost:${port}`,
  dbFile: process.env.DB_FILE || path.join(__dirname, '..', 'data', 'app.db'),
  sessionSecret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  bcryptRounds: Number(process.env.BCRYPT_ROUNDS) || 12,
  maxFailed: Number(process.env.MAX_FAILED) || 5,
  lockMinutes: Number(process.env.LOCK_MINUTES) || 15,
  activateHours: 24,
  resetMinutes: 60,
  smtp: process.env.SMTP_HOST ? {
    host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT) || 587,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
    from: process.env.SMTP_FROM || 'no-reply@secure-accounts.local',
  } : null,
  oidc: process.env.GOOGLE_CLIENT_ID ? {
    name: 'Google',
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    userinfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
    scope: 'openid email profile',
    google: true,
  } : {
    name: 'Dev IdP',
    clientId: 'secure-accounts-client',
    clientSecret: crypto.randomBytes(16).toString('hex'),
    authorizationEndpoint: `${process.env.BASE_URL || `http://localhost:${port}`}/idp/authorize`,
    tokenEndpoint: '', userinfoEndpoint: '',
    scope: 'openid email profile',
  },
  adminEmail: process.env.ADMIN_EMAIL || 'admin@example.com',
  adminPassword: process.env.ADMIN_PASSWORD || `${crypto.randomBytes(9).toString('base64url')}!1aA`,
  adminPasswordFromEnv: !!process.env.ADMIN_PASSWORD,
};
