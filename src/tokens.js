const crypto = require('crypto');
const hash = (t) => crypto.createHash('sha256').update(t).digest('hex');

module.exports = function tokens(db) {
  return {
    create(userId, type, ttlMs) {
      db.prepare('UPDATE tokens SET used = 1 WHERE user_id = ? AND type = ? AND used = 0').run(userId, type);
      const raw = crypto.randomBytes(32).toString('hex');
      db.prepare('INSERT INTO tokens (user_id,type,token_hash,expires_at) VALUES (?,?,?,?)')
        .run(userId, type, hash(raw), Date.now() + ttlMs);
      return raw;
    },
    check(raw, type) {
      const row = db.prepare('SELECT * FROM tokens WHERE token_hash = ? AND type = ?').get(hash(String(raw)), type);
      if (!row) return { error: 'invalid' };
      if (row.used) return { error: 'used' };
      if (row.expires_at < Date.now()) return { error: 'expired' };
      return { userId: row.user_id, id: row.id };
    },
    consume(id) { db.prepare('UPDATE tokens SET used = 1 WHERE id = ?').run(id); },
  };
};
