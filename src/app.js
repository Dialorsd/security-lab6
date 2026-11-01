const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const svgCaptcha = require('svg-captcha');
const QRCode = require('qrcode');
const { generateSecret, generateURI, verifySync } = require('otplib');

const config = require('./config');
const { open } = require('./db');
const { validatePassword, RULES } = require('./policy');
const createMailer = require('./mailer');
const createTokens = require('./tokens');
const idp = require('./idp');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 4);

function createApp({ db = open(), opts = {} } = {}) {
  const cfg = { ...config, ...opts };
  const app = express();
  const mailer = createMailer(db);
  const tokens = createTokens(db);
  app.locals.db = db;

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '..', 'views'));
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(express.static(path.join(__dirname, '..', 'public')));
  app.use(express.urlencoded({ extended: false }));
  app.use(session({
    name: 'sid', secret: cfg.sessionSecret, resave: false, saveUninitialized: true,
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 2 * 60 * 60 * 1000 },
  }));

  const log = (req, { userId = null, email = null, result, reason = null }) =>
    db.prepare('INSERT INTO login_log (user_id,email,ip,user_agent,result,reason) VALUES (?,?,?,?,?,?)')
      .run(userId, email, req.ip, String(req.get('user-agent') || '').slice(0, 200), result, reason);
  const getUser = (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  const byEmail = (e) => db.prepare('SELECT * FROM users WHERE email = ?').get(String(e || '').trim());
  const flash = (req, type, text) => { req.session.flash = { type, text }; };

  app.use((req, res, next) => {
    if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex');
    res.locals.csrf = req.session.csrf;
    res.locals.user = req.session.userId ? getUser(req.session.userId) : null;
    if (req.session.userId && !res.locals.user) delete req.session.userId;
    res.locals.flash = req.session.flash; delete req.session.flash;
    res.locals.oidcName = cfg.oidc.name;
    res.locals.rules = RULES.map((r) => r.text);
    next();
  });
  app.use((req, res, next) => {
    if (req.method === 'POST' && !req.path.startsWith('/idp/token')) {
      const t = req.body && req.body._csrf;
      if (!t || t !== req.session.csrf) return res.status(403).render('error', { title: '403', message: 'Недійсний CSRF-токен.' });
    }
    next();
  });
  const requireAuth = (req, res, next) => (res.locals.user ? next() : res.redirect('/login'));
  const requireRole = (role) => (req, res, next) => {
    if (!res.locals.user) return res.redirect('/login');
    if (res.locals.user.role !== role) return res.status(403).render('error', { title: '403 Заборонено', message: 'Недостатньо прав для перегляду цієї сторінки (RBAC).' });
    next();
  };
  const loginSession = (req, user, cb) => {
    req.session.regenerate((err) => {
      if (err) throw err;
      req.session.userId = user.id;
      req.session.csrf = crypto.randomBytes(24).toString('hex');
      cb();
    });
  };

  app.get('/', (req, res) => res.render('home', { title: 'Головна' }));

  app.get('/captcha', (req, res) => {
    const c = svgCaptcha.create({ size: 5, noise: 3, color: true, ignoreChars: '0oO1iIl', background: '#fffdf5' });
    req.session.captcha = { text: (cfg.testCaptcha || c.text).toLowerCase(), exp: Date.now() + 5 * 60_000 };
    res.type('image/svg+xml').set('Cache-Control', 'no-store').send(c.data);
  });
  const captchaOk = (req) => {
    const c = req.session.captcha; delete req.session.captcha;
    return !!c && c.exp > Date.now() && String(req.body.captcha || '').trim().toLowerCase() === c.text;
  };

  app.get('/register', (req, res) => res.render('register', { title: 'Реєстрація', errors: [], form: {} }));
  app.post('/register', async (req, res) => {
    const form = { name: String(req.body.name || '').trim(), email: String(req.body.email || '').trim() };
    const errors = [];
    if (form.name.length < 2 || form.name.length > 60) errors.push("Вкажіть ім'я (2–60 символів).");
    if (!EMAIL_RE.test(form.email)) errors.push('Некоректний email.');
    if (req.body.password !== req.body.confirm) errors.push('Паролі не збігаються.');
    const pwErr = validatePassword(req.body.password, form);
    if (pwErr.length) errors.push(`Пароль не відповідає політиці: ${pwErr.join('; ')}.`);
    if (!captchaOk(req)) errors.push('Невірна CAPTCHA.');
    if (!errors.length && byEmail(form.email)) errors.push('Користувач з таким email уже існує.');
    if (errors.length) return res.status(400).render('register', { title: 'Реєстрація', errors, form });

    const hash = await bcrypt.hash(req.body.password, cfg.bcryptRounds);
    const { lastInsertRowid } = db.prepare('INSERT INTO users (email,name,password_hash) VALUES (?,?,?)').run(form.email, form.name, hash);
    const raw = tokens.create(lastInsertRowid, 'activate', cfg.activateHours * 3600_000);
    await mailer.send(form.email, 'Підтвердіть реєстрацію',
      `Вітаємо, ${form.name}!\n\nДля активації облікового запису перейдіть за посиланням (діє ${cfg.activateHours} год):\n${cfg.baseUrl}/activate/${raw}\n`);
    log(req, { userId: lastInsertRowid, email: form.email, result: 'register' });
    flash(req, 'ok', 'Реєстрацію виконано. Перевірте пошту та активуйте обліковий запис (див. /mailbox).');
    res.redirect('/login');
  });

  app.get('/activate/:token', (req, res) => {
    const t = tokens.check(req.params.token, 'activate');
    if (t.error) {
      const m = { invalid: 'Недійсне посилання активації.', used: 'Посилання вже використано.', expired: 'Термін дії посилання минув. Запросіть новий лист.' }[t.error];
      return res.status(400).render('message', { title: 'Активація', ok: false, message: m, link: ['/resend', 'Надіслати лист повторно'] });
    }
    db.prepare('UPDATE users SET is_active = 1 WHERE id = ?').run(t.userId);
    tokens.consume(t.id);
    log(req, { userId: t.userId, email: getUser(t.userId).email, result: 'activated' });
    res.render('message', { title: 'Активація', ok: true, message: 'Email підтверджено, обліковий запис активовано. Тепер можна увійти.', link: ['/login', 'Перейти до входу'] });
  });
  app.get('/resend', (req, res) => res.render('email_form', { title: 'Повторний лист активації', action: '/resend', hint: 'Вкажіть email, і ми надішлемо новий лист активації.' }));
  app.post('/resend', async (req, res) => {
    const u = byEmail(req.body.email);
    if (u && !u.is_active) {
      const raw = tokens.create(u.id, 'activate', cfg.activateHours * 3600_000);
      await mailer.send(u.email, 'Підтвердіть реєстрацію', `Посилання активації (діє ${cfg.activateHours} год):\n${cfg.baseUrl}/activate/${raw}\n`);
    }
    flash(req, 'ok', 'Якщо обліковий запис існує й не активований, лист надіслано.');
    res.redirect('/login');
  });

  app.get('/login', (req, res) => res.render('login', { title: 'Вхід', error: null, email: '' }));
  app.post('/login', async (req, res) => {
    const email = String(req.body.email || '').trim();
    const fail = (msg, code = 401) => res.status(code).render('login', { title: 'Вхід', error: msg, email });
    const u = byEmail(email);
    if (!u) {
      await bcrypt.compare(String(req.body.password || ''), DUMMY_HASH);
      log(req, { email, result: 'fail', reason: 'unknown_user' });
      return fail('Невірний email або пароль.');
    }
    if (u.is_blocked) { log(req, { userId: u.id, email, result: 'denied', reason: 'blocked_by_admin' }); return fail('Обліковий запис заблоковано адміністратором.', 403); }
    if (u.locked_until && u.locked_until > Date.now()) {
      const mins = Math.ceil((u.locked_until - Date.now()) / 60000);
      log(req, { userId: u.id, email, result: 'denied', reason: 'locked' });
      return fail(`Забагато невдалих спроб. Обліковий запис тимчасово заблоковано, спробуйте через ${mins} хв.`, 429);
    }
    const ok = u.password_hash && await bcrypt.compare(String(req.body.password || ''), u.password_hash);
    if (!ok) {
      const attempts = u.failed_attempts + 1;
      if (attempts >= cfg.maxFailed) {
        db.prepare('UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?').run(Date.now() + cfg.lockMinutes * 60_000, u.id);
        log(req, { userId: u.id, email, result: 'locked', reason: `${attempts} невдалих спроб` });
        return fail(`Забагато невдалих спроб (${cfg.maxFailed}). Обліковий запис заблоковано на ${cfg.lockMinutes} хв.`, 429);
      }
      db.prepare('UPDATE users SET failed_attempts = ? WHERE id = ?').run(attempts, u.id);
      log(req, { userId: u.id, email, result: 'fail', reason: 'bad_password' });
      return fail(`Невірний email або пароль. Залишилось спроб: ${cfg.maxFailed - attempts}.`);
    }
    if (!u.is_active) { log(req, { userId: u.id, email, result: 'denied', reason: 'not_activated' }); return fail('Email не підтверджено. Активуйте обліковий запис за посиланням з листа.', 403); }
    db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(u.id);
    if (u.totp_enabled) {
      req.session.pending2fa = { userId: u.id, exp: Date.now() + 5 * 60_000, tries: 0 };
      return res.redirect('/2fa');
    }
    loginSession(req, u, () => { log(req, { userId: u.id, email, result: 'success' }); res.redirect('/profile'); });
  });

  app.get('/2fa', (req, res) => {
    if (!req.session.pending2fa) return res.redirect('/login');
    res.render('twofa_login', { title: 'Двофакторна автентифікація', error: null });
  });
  app.post('/2fa', (req, res) => {
    const p = req.session.pending2fa;
    if (!p || p.exp < Date.now()) { delete req.session.pending2fa; flash(req, 'err', 'Сесію підтвердження завершено, увійдіть знову.'); return res.redirect('/login'); }
    const u = getUser(p.userId);
    const code = String(req.body.code || '').replace(/\s/g, '');
    const r = verifySync({ secret: u.totp_secret, token: code, epochTolerance: 30 });
    if (!r.valid) {
      p.tries += 1;
      log(req, { userId: u.id, email: u.email, result: 'fail', reason: '2fa_bad_code' });
      if (p.tries >= 5) { delete req.session.pending2fa; flash(req, 'err', 'Забагато невірних кодів 2FA. Увійдіть знову.'); return res.redirect('/login'); }
      return res.status(401).render('twofa_login', { title: 'Двофакторна автентифікація', error: 'Невірний код.' });
    }
    loginSession(req, u, () => { log(req, { userId: u.id, email: u.email, result: 'success', reason: '2fa' }); res.redirect('/profile'); });
  });

  app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

  app.get('/profile', requireAuth, (req, res) => res.render('profile', { title: 'Профіль' }));
  app.get('/profile/2fa', requireAuth, async (req, res) => {
    const u = res.locals.user;
    if (u.totp_enabled) return res.redirect('/profile');
    const secret = req.session.totpSetup || (req.session.totpSetup = generateSecret());
    const uri = generateURI({ issuer: 'Lab6', label: u.email, secret });
    res.render('twofa_setup', { title: 'Увімкнення 2FA', secret, qr: await QRCode.toDataURL(uri), error: null });
  });
  app.post('/profile/2fa/enable', requireAuth, async (req, res) => {
    const secret = req.session.totpSetup;
    if (!secret) return res.redirect('/profile/2fa');
    const r = verifySync({ secret, token: String(req.body.code || '').replace(/\s/g, ''), epochTolerance: 30 });
    if (!r.valid) {
      const uri = generateURI({ issuer: 'Lab6', label: res.locals.user.email, secret });
      return res.status(400).render('twofa_setup', { title: 'Увімкнення 2FA', secret, qr: await QRCode.toDataURL(uri), error: 'Невірний код. Спробуйте ще раз.' });
    }
    db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?').run(secret, res.locals.user.id);
    delete req.session.totpSetup;
    log(req, { userId: res.locals.user.id, email: res.locals.user.email, result: '2fa_enabled' });
    flash(req, 'ok', 'Двофакторну автентифікацію увімкнено.');
    res.redirect('/profile');
  });
  app.post('/profile/2fa/disable', requireAuth, async (req, res) => {
    const u = res.locals.user;
    const okPw = u.password_hash ? await bcrypt.compare(String(req.body.password || ''), u.password_hash) : true;
    if (!okPw) { flash(req, 'err', 'Невірний пароль — 2FA не вимкнено.'); return res.redirect('/profile'); }
    db.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?').run(u.id);
    log(req, { userId: u.id, email: u.email, result: '2fa_disabled' });
    flash(req, 'ok', 'Двофакторну автентифікацію вимкнено.');
    res.redirect('/profile');
  });

  app.get('/forgot', (req, res) => res.render('email_form', { title: 'Відновлення пароля', action: '/forgot', hint: 'Вкажіть email — ми надішлемо посилання для скидання пароля.' }));
  app.post('/forgot', async (req, res) => {
    const u = byEmail(req.body.email);
    if (u && u.is_active && !u.is_blocked) {
      const raw = tokens.create(u.id, 'reset', cfg.resetMinutes * 60_000);
      await mailer.send(u.email, 'Відновлення пароля',
        `Ви (або хтось інший) запросили скидання пароля.\nПосилання діє ${cfg.resetMinutes} хв і працює один раз:\n${cfg.baseUrl}/reset/${raw}\n\nЯкщо це були не ви — просто проігноруйте лист.`);
      log(req, { userId: u.id, email: u.email, result: 'reset_requested' });
    }
    flash(req, 'ok', 'Якщо такий обліковий запис існує, на вказаний email надіслано інструкцію (див. /mailbox).');
    res.redirect('/login');
  });
  app.get('/reset/:token', (req, res) => {
    const t = tokens.check(req.params.token, 'reset');
    if (t.error) return res.status(400).render('message', { title: 'Відновлення', ok: false, message: { invalid: 'Недійсне посилання.', used: 'Посилання вже використано.', expired: 'Термін дії посилання минув.' }[t.error], link: ['/forgot', 'Запросити нове'] });
    res.render('reset', { title: 'Новий пароль', token: req.params.token, errors: [] });
  });
  app.post('/reset/:token', async (req, res) => {
    const t = tokens.check(req.params.token, 'reset');
    if (t.error) return res.status(400).render('message', { title: 'Відновлення', ok: false, message: 'Посилання недійсне, використане або прострочене.', link: ['/forgot', 'Запросити нове'] });
    const u = getUser(t.userId);
    const errors = [];
    if (req.body.password !== req.body.confirm) errors.push('Паролі не збігаються.');
    const pe = validatePassword(req.body.password, u);
    if (pe.length) errors.push(`Пароль не відповідає політиці: ${pe.join('; ')}.`);
    if (!errors.length && u.password_hash && await bcrypt.compare(req.body.password, u.password_hash)) errors.push('Новий пароль не повинен збігатися зі старим.');
    if (errors.length) return res.status(400).render('reset', { title: 'Новий пароль', token: req.params.token, errors });
    db.prepare('UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?').run(await bcrypt.hash(req.body.password, cfg.bcryptRounds), u.id);
    tokens.consume(t.id);
    log(req, { userId: u.id, email: u.email, result: 'password_reset' });
    await mailer.send(u.email, 'Пароль змінено', 'Пароль до вашого облікового запису було змінено. Якщо це були не ви — негайно зверніться до адміністратора.');
    flash(req, 'ok', 'Пароль змінено. Увійдіть з новим паролем.');
    res.redirect('/login');
  });

  app.use('/idp', idp());
  app.get('/auth/oidc', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    req.session.oidcState = state;
    const u = new URL(cfg.oidc.authorizationEndpoint);
    u.search = new URLSearchParams({
      response_type: 'code', client_id: cfg.oidc.clientId, redirect_uri: `${cfg.baseUrl}/auth/oidc/callback`,
      scope: cfg.oidc.scope, state, ...(cfg.oidc.google ? { prompt: 'select_account' } : {}),
    }).toString();
    res.redirect(u.toString());
  });
  app.get('/auth/oidc/callback', async (req, res) => {
    try {
      if (!req.query.state || req.query.state !== req.session.oidcState) throw new Error('Невірний state (можлива CSRF-атака).');
      delete req.session.oidcState;
      if (!req.query.code) throw new Error(`Провайдер повернув помилку: ${req.query.error || 'немає code'}`);
      const self = `${req.protocol}://${req.get('host')}`;
      const tokenUrl = cfg.oidc.google ? cfg.oidc.tokenEndpoint : `${self}/idp/token`;
      const userinfoUrl = cfg.oidc.google ? cfg.oidc.userinfoEndpoint : `${self}/idp/userinfo`;
      const tr = await fetch(tokenUrl, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code: String(req.query.code), client_id: cfg.oidc.clientId, client_secret: cfg.oidc.clientSecret, redirect_uri: `${cfg.baseUrl}/auth/oidc/callback` }),
      });
      const tok = await tr.json();
      if (!tok.access_token) throw new Error('Не вдалося отримати access token.');
      const info = await (await fetch(userinfoUrl, { headers: { authorization: `Bearer ${tok.access_token}` } })).json();
      if (!info.sub || !info.email || info.email_verified === false) throw new Error('Провайдер не підтвердив email.');
      let u = db.prepare('SELECT * FROM users WHERE oidc_sub = ?').get(info.sub) || byEmail(info.email);
      if (u && u.is_blocked) { log(req, { userId: u.id, email: u.email, result: 'denied', reason: 'blocked_by_admin' }); throw new Error('Обліковий запис заблоковано адміністратором.'); }
      if (!u) {
        const id = db.prepare('INSERT INTO users (email,name,oidc_sub,is_active) VALUES (?,?,?,1)').run(info.email, info.name || info.email, info.sub).lastInsertRowid;
        u = getUser(id);
      } else {
        db.prepare('UPDATE users SET oidc_sub = COALESCE(oidc_sub, ?), is_active = 1 WHERE id = ?').run(info.sub, u.id);
        u = getUser(u.id);
      }
      if (u.totp_enabled) { req.session.pending2fa = { userId: u.id, exp: Date.now() + 5 * 60_000, tries: 0 }; return res.redirect('/2fa'); }
      loginSession(req, u, () => { log(req, { userId: u.id, email: u.email, result: 'success', reason: `oidc:${cfg.oidc.name}` }); res.redirect('/profile'); });
    } catch (e) {
      log(req, { result: 'fail', reason: `oidc: ${e.message}` });
      flash(req, 'err', `Вхід через ${cfg.oidc.name} не вдався: ${e.message}`);
      res.redirect('/login');
    }
  });

  app.get('/admin', requireRole('admin'), (req, res) => {
    const users = db.prepare('SELECT * FROM users ORDER BY id').all().map((u) => ({ ...u, locked: !!(u.locked_until && u.locked_until > Date.now()) }));
    res.render('admin_users', { title: 'Адмін-панель: користувачі', users });
  });
  const adminAction = (fn) => [requireRole('admin'), (req, res) => {
    const id = Number(req.params.id);
    const target = getUser(id);
    if (!target) return res.status(404).render('error', { title: '404', message: 'Користувача не знайдено.' });
    if (id === res.locals.user.id && !fn.allowSelf) { flash(req, 'err', 'Не можна виконати цю дію над власним обліковим записом.'); return res.redirect('/admin'); }
    fn(target); log(req, { userId: id, email: target.email, result: `admin_${fn.label}`, reason: `by ${res.locals.user.email}` });
    flash(req, 'ok', `Готово: ${fn.label} → ${target.email}`);
    res.redirect('/admin');
  }];
  const block = (t) => db.prepare('UPDATE users SET is_blocked = 1 WHERE id = ?').run(t.id); block.label = 'block';
  const unblock = (t) => db.prepare('UPDATE users SET is_blocked = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?').run(t.id); unblock.label = 'unblock'; unblock.allowSelf = true;
  const promote = (t) => db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(t.id); promote.label = 'make_admin';
  const demote = (t) => db.prepare("UPDATE users SET role = 'user' WHERE id = ?").run(t.id); demote.label = 'make_user';
  app.post('/admin/users/:id/block', ...adminAction(block));
  app.post('/admin/users/:id/unblock', ...adminAction(unblock));
  app.post('/admin/users/:id/promote', ...adminAction(promote));
  app.post('/admin/users/:id/demote', ...adminAction(demote));
  app.get('/admin/log', requireRole('admin'), (req, res) => {
    const rows = db.prepare('SELECT * FROM login_log ORDER BY id DESC LIMIT 200').all();
    res.render('admin_log', { title: 'Адмін-панель: журнал входів', rows });
  });

  app.get('/mailbox', (req, res) => {
    const mails = db.prepare('SELECT * FROM mails ORDER BY id DESC LIMIT 50').all();
    const linkify = (s) => s.replace(/(https?:\/\/[^\s]+)/g, '<a href="$1">$1</a>');
    res.render('mailbox', { title: 'Dev-поштова скринька', mails, linkify });
  });

  app.use((req, res) => res.status(404).render('error', { title: '404', message: 'Сторінку не знайдено.' }));
  app.use((err, req, res, _next) => { console.error(err); res.status(500).render('error', { title: '500', message: 'Внутрішня помилка сервера.' }); });
  return app;
}

function seedAdmin(db) {
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(config.adminEmail)) return;
  db.prepare("INSERT INTO users (email,name,password_hash,role,is_active) VALUES (?,?,?,'admin',1)")
    .run(config.adminEmail, 'Адміністратор', bcrypt.hashSync(config.adminPassword, config.bcryptRounds));
  if (!config.adminPasswordFromEnv) console.log(`Створено адміна ${config.adminEmail}, пароль (показано один раз): ${config.adminPassword}`);
}

module.exports = { createApp, seedAdmin };
