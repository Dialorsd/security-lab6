(function () {
  var pw = document.getElementById('password');
  if (pw) {
    var texts = JSON.parse(document.getElementById('rules').dataset.rules);
    var tests = [
      function (p) { return p.length >= 8; },
      function (p) { return /\p{Lu}/u.test(p); },
      function (p) { return /\p{Ll}/u.test(p); },
      function (p) { return /\d/.test(p); },
      function (p) { return /[^\p{L}\d\s]/u.test(p); }
    ];
    var ul = document.getElementById('rules');
    texts.forEach(function (t) { var li = document.createElement('li'); li.textContent = t; ul.appendChild(li); });
    var bar = document.getElementById('meterBar'), label = document.getElementById('meterText');
    var names = ['Дуже слабкий', 'Слабкий', 'Задовільний', 'Добрий', 'Надійний', 'Відмінний'];
    var colors = ['#c53030', '#c53030', '#dd6b20', '#b7791f', '#2f855a', '#1b8a4b'];
    pw.addEventListener('input', function () {
      var p = pw.value, score = 0;
      tests.forEach(function (t, i) { var ok = t(p); ul.children[i].className = ok ? 'ok' : ''; if (ok) score++; });
      if (p.length >= 12 && score === 5) score = 5; else if (score === 5) score = 4;
      if (!p) score = 0;
      bar.style.width = (p ? Math.max(8, score * 20) : 0) + '%';
      bar.style.background = colors[score];
      label.textContent = p ? 'Надійність: ' + names[score] : 'Введіть пароль';
    });
  }
  var img = document.getElementById('captchaImg'), btn = document.getElementById('captchaReload');
  if (img && btn) btn.addEventListener('click', function () { img.src = '/captcha?t=' + Date.now(); });
})();
