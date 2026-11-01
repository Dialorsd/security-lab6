const COMMON = ['password', 'qwerty', '123456', '12345678', 'qwerty123', 'admin', 'letmein', 'welcome',
  'iloveyou', 'password1', 'abc123', '111111', 'пароль', 'йцукен', 'qazwsx'];

const RULES = [
  { id: 'len', text: 'Щонайменше 8 символів', test: (p) => p.length >= 8 },
  { id: 'upper', text: 'Велика літера (A–Z / А–Я)', test: (p) => /\p{Lu}/u.test(p) },
  { id: 'lower', text: 'Мала літера (a–z / а–я)', test: (p) => /\p{Ll}/u.test(p) },
  { id: 'digit', text: 'Цифра (0–9)', test: (p) => /\d/.test(p) },
  { id: 'special', text: 'Спеціальний символ (!@#$%^&* тощо)', test: (p) => /[^\p{L}\d\s]/u.test(p) },
];

function validatePassword(password, { email = '', name = '' } = {}) {
  const errors = [];
  const p = String(password || '');
  for (const r of RULES) if (!r.test(p)) errors.push(r.text);
  if (p.length > 128) errors.push('Не більше 128 символів');
  const low = p.toLowerCase();
  if (COMMON.some((c) => low.includes(c))) errors.push('Не повинен містити поширені слова/послідовності (password, qwerty, 123456…)');
  const local = String(email).split('@')[0].toLowerCase();
  if (local.length >= 3 && low.includes(local)) errors.push('Не повинен містити частину вашого email');
  const n = String(name).toLowerCase();
  if (n.length >= 3 && low.includes(n)) errors.push("Не повинен містити ваше ім'я");
  return errors;
}

module.exports = { validatePassword, RULES };
