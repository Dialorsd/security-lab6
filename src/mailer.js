const nodemailer = require('nodemailer');
const config = require('./config');

module.exports = function createMailer(db) {
  const transport = config.smtp ? nodemailer.createTransport(config.smtp) : null;
  const insert = db.prepare('INSERT INTO mails (to_addr, subject, body) VALUES (?,?,?)');
  return {
    async send(to, subject, body) {
      insert.run(to, subject, body);
      if (transport) {
        try { await transport.sendMail({ from: config.smtp.from, to, subject, text: body }); }
        catch (e) { console.error('SMTP error:', e.message); }
      }
    },
  };
};
