const config = require('./src/config');
const { open } = require('./src/db');
const { createApp, seedAdmin } = require('./src/app');
const db = open();
seedAdmin(db);
createApp({ db }).listen(config.port, () => console.log(`Secure Accounts: ${config.baseUrl}  (admin: ${config.adminEmail})`));
