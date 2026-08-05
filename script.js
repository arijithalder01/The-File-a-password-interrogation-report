/* ==========================================================================
   The File — password interrogation report
   Everything runs locally. No password is ever read into a network call.
   ========================================================================== */

const YEAR_SECONDS = 31557600;
const COMPROMISED_THRESHOLD_LOG10 = Math.log10(YEAR_SECONDS); // under 1 year = compromised

const ATTACKERS = [
  { name: 'A stranger, guessing by hand', desc: 'typing tries one at a time', rate: 0.5 },
  { name: 'An unthrottled login form', desc: 'a script hammering the login page', rate: 25 },
  { name: 'A hobbyist\u2019s laptop', desc: 'offline attack against a stolen hash', rate: 1e9 },
  { name: 'A gaming rig with a serious GPU', desc: 'consumer hardware, purpose-built', rate: 1e10 },
  { name: 'A small criminal botnet', desc: 'thousands of compromised machines', rate: 1e11 },
  { name: 'A funded cracking cluster', desc: 'cloud GPUs rented for the job', rate: 1e13 },
  { name: 'A nation-state', desc: 'custom silicon, no budget ceiling', rate: 1e15 },
];

const COMMON_PASSWORDS = new Set([
  '123456','123456789','password','12345678','qwerty','123123','1q2w3e4r','111111',
  'iloveyou','000000','1234','1234567','password1','654321','123321','666666',
  'qwertyuiop','7777777','1qaz2wsx','dragon','sunshine','princess','letmein',
  'monkey','football','abc123','trustno1','baseball','superman','master',
  '696969','shadow','michael','mustang','jordan','freedom','hunter','ashley',
  'admin','welcome','login','passw0rd','starwars','whatever','qazwsx','zaq1zaq1',
  'batman','000000','121212','flower','hottie','loveme','1qaz2wsx3edc',
]);

const pwInput = document.getElementById('pwInput');
const toggleBtn = document.getElementById('toggleVisibility');
const meterFill = document.getElementById('meterFill');
const meterLabel = document.getElementById('meterLabel');
const profileList = document.getElementById('profileList');
const entropyBitsEl = document.getElementById('entropyBits');
const entropyNoteEl = document.getElementById('entropyNote');
const logEntriesEl = document.getElementById('logEntries');
const leakBanner = document.getElementById('leakBanner');
const caseNumberEl = document.getElementById('caseNumber');

caseNumberEl.textContent = String(Math.floor(1000 + Math.random() * 8999));

let debounceHandle = null;

pwInput.addEventListener('input', () => {
  clearTimeout(debounceHandle);
  debounceHandle = setTimeout(() => render(pwInput.value), 120);
});

toggleBtn.addEventListener('click', () => {
  const showing = pwInput.type === 'text';
  pwInput.type = showing ? 'password' : 'text';
  toggleBtn.textContent = showing ? 'SHOW' : 'HIDE';
});

/* ---------------------------------------------------------------------- */
/* Character pool + entropy                                                */
/* ---------------------------------------------------------------------- */
function analyze(password) {
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSymbol = /[^a-zA-Z0-9]/.test(password);

  let pool = 0;
  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigit) pool += 10;
  if (hasSymbol) pool += 32;

  const length = password.length;
  const bits = length > 0 && pool > 0 ? length * Math.log2(pool) : 0;

  return { hasLower, hasUpper, hasDigit, hasSymbol, pool, length, bits };
}

/* ---------------------------------------------------------------------- */
/* Crack-time estimation, kept entirely in log10 space to survive huge     */
/* keyspaces without overflowing to Infinity.                              */
/* ---------------------------------------------------------------------- */
function log10SecondsToCrack(bits, ratePerSecond) {
  if (bits <= 0) return -Infinity;
  // average-case: attacker expects to find it after searching half the keyspace
  return (bits - 1) * Math.log10(2) - Math.log10(ratePerSecond);
}

function humanizeLog10Seconds(log10s) {
  if (!isFinite(log10s) || log10s < -1) return 'instantly';
  if (log10s < 0) return 'under a second';

  const units = [
    ['seconds', 0],
    ['minutes', Math.log10(60)],
    ['hours', Math.log10(3600)],
    ['days', Math.log10(86400)],
    ['months', Math.log10(2629800)],
  ];

  const yearsLog10 = log10s - Math.log10(YEAR_SECONDS);

  if (yearsLog10 < 0) {
    for (let i = units.length - 1; i >= 0; i--) {
      const [unit, div] = units[i];
      if (log10s >= div) {
        const value = Math.pow(10, log10s - div);
        return `${formatNumber(value)} ${unit}`;
      }
    }
    return 'under a second';
  }

  if (yearsLog10 < 6) {
    return `${formatNumber(Math.pow(10, yearsLog10))} years`;
  }
  if (yearsLog10 < 100) {
    return `~10^${Math.round(yearsLog10)} years`;
  }
  return 'longer than the universe has existed, many times over';
}

function formatNumber(n) {
  if (n < 10) return n.toFixed(1);
  return Math.round(n).toLocaleString();
}

/* ---------------------------------------------------------------------- */
/* Rendering                                                                */
/* ---------------------------------------------------------------------- */
function render(password) {
  const isCommon = password.length > 0 && COMMON_PASSWORDS.has(password.toLowerCase());
  const a = analyze(password);

  renderMeter(a, password.length, isCommon);
  renderProfile(a);
  renderEntropy(a);
  renderLog(a, isCommon);
  leakBanner.classList.toggle('hidden', !isCommon);
}

function renderMeter(a, length, isCommon) {
  if (length === 0) {
    meterFill.style.width = '0%';
    meterFill.style.background = 'var(--stamp-red)';
    meterLabel.textContent = 'AWAITING STATEMENT';
    return;
  }
  if (isCommon) {
    meterFill.style.width = '100%';
    meterFill.style.background = 'var(--stamp-red)';
    meterLabel.textContent = 'ON THE LEAK LIST';
    return;
  }
  const pct = Math.max(4, Math.min(100, (a.bits / 100) * 100));
  meterFill.style.width = pct + '%';
  let label, color;
  if (a.bits < 28) { label = 'WEAK STATEMENT'; color = 'var(--stamp-red)'; }
  else if (a.bits < 45) { label = 'SHAKY ALIBI'; color = '#c98a3a'; }
  else if (a.bits < 65) { label = 'HOLDING UP'; color = '#c9b23a'; }
  else { label = 'AIRTIGHT'; color = 'var(--stamp-green)'; }
  meterFill.style.background = color;
  meterLabel.textContent = label;
}

function renderProfile(a) {
  const items = [
    { met: a.length >= 12, text: `length \u2014 ${a.length} character${a.length === 1 ? '' : 's'} (12+ recommended)` },
    { met: a.hasLower, text: 'contains lowercase letters' },
    { met: a.hasUpper, text: 'contains uppercase letters' },
    { met: a.hasDigit, text: 'contains digits' },
    { met: a.hasSymbol, text: 'contains symbols' },
  ];
  profileList.innerHTML = items.map(item => `
    <li class="${item.met ? 'met' : ''}">
      <span class="mark">${item.met ? '[x]' : '[ ]'}</span>
      <span>${item.text}</span>
    </li>
  `).join('');
}

function renderEntropy(a) {
  entropyBitsEl.textContent = a.length > 0 ? Math.round(a.bits) : '0';
  entropyNoteEl.textContent = a.length > 0
    ? `Keyspace: ${a.pool}^${a.length} possible combinations`
    : 'Keyspace: \u2014';
}

function renderLog(a, isCommon) {
  if (a.length === 0) {
    logEntriesEl.innerHTML = `<p style="font-size:12px;color:var(--ink-faint);padding:10px 0;">The suspect has said nothing yet.</p>`;
    return;
  }

  logEntriesEl.innerHTML = ATTACKERS.map((attacker, i) => {
    let timeText, compromised;
    if (isCommon) {
      timeText = 'already known';
      compromised = true;
    } else {
      const log10s = log10SecondsToCrack(a.bits, attacker.rate);
      timeText = humanizeLog10Seconds(log10s);
      compromised = log10s < COMPROMISED_THRESHOLD_LOG10;
    }
    const stampClass = compromised ? 'stamp-red' : 'stamp-green';
    const stampText = compromised ? 'COMPROMISED' : 'HELD';

    return `
      <div class="log-entry" style="animation-delay:${i * 45}ms">
        <div>
          <span class="log-entry-id">CASE #${String(i + 1).padStart(3, '0')} \u2014 ${attacker.desc}</span>
          <span class="log-entry-name">${attacker.name}</span>
          <span class="log-entry-time">cracked in <strong>${timeText}</strong></span>
        </div>
        <span class="stamp ${stampClass}">${stampText}</span>
      </div>
    `;
  }).join('');
}

/* Initial paint */
render('');
