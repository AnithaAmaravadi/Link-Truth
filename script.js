/* ============================================================
   LINKTRUTH — script.js (keep in SAME folder as index.html)
   ============================================================ */

/* ---------------- helpers ---------------- */
const $ = s => document.querySelector(s);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

/* ---------------- knowledge base ---------------- */
const BRANDS = [
  {n:'Google',      w:'google',    ds:['google.com','google.co','google.co.uk','google.org','youtube.com','youtu.be','goo.gl']},
  {n:'Facebook',    w:'facebook',  ds:['facebook.com','fb.com','fb.me']},
  {n:'Apple',       w:'apple',     ds:['apple.com','icloud.com','me.com']},
  {n:'Amazon',      w:'amazon',    ds:['amazon.com','amazon.co.uk','amazon.in','amazon.de','amzn.to']},
  {n:'Microsoft',   w:'microsoft', ds:['microsoft.com','live.com','office.com','windows.com','aka.ms','microsoftonline.com']},
  {n:'PayPal',      w:'paypal',    ds:['paypal.com','paypal.me']},
  {n:'Netflix',     w:'netflix',   ds:['netflix.com','nflx.video']},
  {n:'Instagram',   w:'instagram', ds:['instagram.com']},
  {n:'WhatsApp',    w:'whatsapp',  ds:['whatsapp.com','wa.me']},
  {n:'eBay',        w:'ebay',      ds:['ebay.com','ebay.co.uk']},
  {n:'LinkedIn',    w:'linkedin',  ds:['linkedin.com','lnkd.in']},
  {n:'X / Twitter', w:'twitter',   ds:['twitter.com','x.com','t.co']},
  {n:'Dropbox',     w:'dropbox',   ds:['dropbox.com']},
  {n:'Steam',       w:'steam',     ds:['steampowered.com','steamcommunity.com']},
  {n:'Chase Bank',  w:'chase',     ds:['chase.com']},
  {n:'Gmail',       w:'gmail',     ds:['gmail.com']},
  {n:'Outlook',     w:'outlook',   ds:['outlook.com']},
  {n:'Binance',     w:'binance',   ds:['binance.com','binance.us']},
  {n:'Coinbase',    w:'coinbase',  ds:['coinbase.com']},
  {n:'Telegram',    w:'telegram',  ds:['telegram.org','t.me']}
];

const SHORTENERS = new Set(['bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd','buff.ly','rebrand.ly','cutt.ly','rb.gy','tiny.cc','shorturl.at','t.ly','lnkd.in','s.id','v.gd','tiny.pl','cutt.us','short.io','bl.ink','bc.vc','amzn.to','soo.gd','tinyurl.to']);
const BAD_TLD   = new Set(['tk','ml','ga','cf','gq']);
const RISKY_TLD = new Set(['xyz','top','icu','click','loan','buzz','cam','gdn','sbs','cfd','cyou','quest','lat','monster','rest','surf','mom','hiphop','fit','bid','win','download','stream','review','party','trade','webcam','date','faith','racing','cricket','kim','men','work','link','site','online','website','store','fun','space']);
const KW = ['verify','verification','update','confirm','secure','security','account','login','signin','password','banking','suspend','unblock','unlock','billing','invoice','refund','winner','prize','bonus','wallet','recover','restricted','appeal','webmail','reactivate'];
const LEET = {'1':'l','!':'i','0':'o','3':'e','4':'a','5':'s','7':'t','8':'b','@':'a','$':'s'};

const deleet = t => t.split('').map(c => LEET[c] || c).join('');

function lev(a, b){
  const m = a.length, n = b.length;
  const d = Array.from({length: m + 1}, (_, i) => [i, ...Array(n).fill(0)]);
  for(let j = 1; j <= n; j++) d[0][j] = j;
  for(let i = 1; i <= m; i++)
    for(let j = 1; j <= n; j++)
      d[i][j] = Math.min(d[i-1][j] + 1, d[i][j-1] + 1, d[i-1][j-1] + (a[i-1] === b[j-1] ? 0 : 1));
  return d[m][n];
}

function entropy(t){
  const f = {};
  for(const c of t) f[c] = (f[c] || 0) + 1;
  let e = 0;
  for(const k in f){ const p = f[k] / t.length; e -= p * Math.log2(p); }
  return e;
}

/* ============================================================
   ANALYSIS ENGINE
   ============================================================ */
function analyze(raw){
  const C = [];
  const add = (name, status, pts, msg) => C.push({name, status, pts, msg});

  let s = String(raw || '').trim().replace(/\s+/g, '');
  if(!s) return null;

  let prepended = false;
  if(!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(s)){ s = 'https://' + s; prepended = true; }

  let u;
  try { u = new URL(s); } catch(e){ return {invalid:true, raw}; }

  const host   = u.hostname.toLowerCase();
  const labels = host.split('.').filter(Boolean);
  const tld    = labels[labels.length - 1] || '';
  const isIP   = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(host) || host.includes(':');

  let base = labels.slice(-2).join('.');
  if(labels.length >= 3){
    const l2 = labels[labels.length - 2];
    if(l2.length <= 3 && ['co','com','net','org','gov','ac','go','edu','or'].includes(l2) && tld.length === 2)
      base = labels.slice(-3).join('.');
  }
  const baseCount = base.split('.').length;

  const proto = u.protocol;
  if(['data:','javascript:','file:','vbscript:','blob:'].includes(proto)){
    add('URL scheme','fail',55,`"${proto}" links can execute code or inject a fake page directly. Never, ever click these from a message.`);
  } else if(proto === 'https:'){
    add('Encrypted protocol','pass',0,'HTTPS is active — the connection to this site would be encrypted.');
  } else if(proto === 'http:'){
    add('Unencrypted protocol','fail',16,'Plain HTTP — anything you type (passwords, card numbers) travels as readable text. Legitimate services use HTTPS.');
  } else {
    add('Unusual protocol','warn',20,`"${proto}" is rarely used in normal browsing and often indicates a trick.`);
  }
  if(prepended) add('No protocol typed','info',0,'You pasted a bare address, so we assumed https:// for the analysis.');

  if(isIP){
    add('Raw IP address','fail',30,'This link points at raw numbers instead of a named domain. Real services don\u2019t hide behind IPs — a classic phishing and malware pattern.');
  } else if(['localhost','127.0.0.1'].includes(host)){
    add('Local address','info',0,'This points at the current device itself, not the internet.');
  }

  if(!isIP){
    if(BAD_TLD.has(tld))
      add('High-abuse TLD','fail',30,`".${tld}" comes from a free/abused zone that tops global phishing charts. Legitimate organisations essentially never use it.`);
    else if(RISKY_TLD.has(tld))
      add('Risky TLD','warn',12,`".${tld}" is a cheap bulk domain ending that appears heavily in abuse listings. Not proof of fraud, but a strong smell.`);
    else
      add('Standard TLD','pass',0,`".${tld}" is a common, reputable domain ending.`);

    let hit = null, legit = null;
    for(const b of BRANDS){
      if(b.ds.includes(base)){ legit = b; break; }
      for(const lab of labels){
        const dl = deleet(lab);
        if(dl === b.w || dl.startsWith(b.w) || (dl.length - b.w.length <= 10 && dl.endsWith('-' + b.w))){ hit = b; break; }
        if(dl.length >= 4 && b.w.length >= 4){
          const dist = lev(dl, b.w);
          if(dist > 0 && dist <= 2 && Math.abs(dl.length - b.w.length) <= 2){ hit = b; break; }
        }
      }
      if(hit) break;
    }
    if(legit) add('Known brand domain','pass',0,`This is the genuine base domain of ${legit.n}. The name itself checks out.`);
    else if(hit) add(`Impersonating ${hit.n}`,'fail',40,`The link looks and reads like ${hit.n} (possibly with swapped letters like 0→o or 1→l), but the real address is "${hit.ds[0]}". Treating this as impersonation.`);

    const pp = (u.pathname + u.search).toLowerCase();
    for(const b of BRANDS){
      if(!legit && base !== b.ds[0] && pp.includes(b.w)){
        add('Brand word in path','warn',10,`The path mentions "${b.w}", but the domain does not belong to ${b.n} — a common bait technique.`);
        break;
      }
    }
  }

  if(SHORTENERS.has(host) || SHORTENERS.has(base))
    add('Link shortener','warn',18,`"${host}" completely hides the real destination. Expand it (any "URL expander" tool) before trusting it.`);

  if(u.href.includes('@'))
    add('@ decoy','fail',24,'Everything before the @ is a decoy — the browser actually visits what comes AFTER it. A deliberate misdirection trick.');
  if(u.pathname.includes('//'))
    add('Double slashes','warn',8,'Extra "//" inside the path is often used to confuse redirect logic and human eyes.');
  if(u.port && !['80','443'].includes(u.port))
    add('Unusual port','warn',10,`Non-standard port :${u.port} — everyday websites don\u2019t need one.`);
  if(u.href.length > 120)
    add('Oversized URL','warn',6,`${u.href.length} characters long. Attackers pad links so the important part scrolls out of sight.`);

  if(!isIP){
    const subCount = labels.length - baseCount;
    if(subCount >= 4) add('Deep subdomain chain','warn',14,`${subCount} subdomain levels. The true owner is only the last part — the rest is costume jewellery.`);
    else if(subCount === 3) add('Long subdomain chain','warn',6,'Three subdomain levels — check carefully which part is the real domain.');

    if((host.match(/-/g) || []).length >= 3)
      add('Hyphen-stitched name','warn',8,'Fraud domains often glue trust words together: "secure-paypal-verify-now".');

    if(labels.some(l => l.startsWith('xn--')))
      add('Punycode homograph','fail',26,'"xn--" labels hide foreign look-alike letters (а instead of a). This is a homograph attack vector.');

    for(const l of labels){
      if(l.length >= 12 && entropy(l) > 3.6){
        add('Randomized label','warn',10,`"${l}" looks machine-generated — typical of disposable phishing domains.`);
        break;
      }
    }
  }

  if(/\.(exe|apk|scr|bat|cmd|msi|jar|iso|vbs)$/i.test(u.pathname))
    add('Executable download','fail',22,'This link downloads a program file — the favourite delivery method for malware. Do not open it.');

  const hay = (u.pathname + u.search).toLowerCase();
  const found = KW.filter(k => hay.includes(k));
  if(found.length >= 4) add('Urgency keyword stack','warn',16,`Stacked bait words (${found.slice(0,5).join(', ')}…) — the fingerprint of a credential-harvesting kit.`);
  else if(found.length >= 2) add('Suspicious keywords','warn',8,`Contains pressure words like ${found.slice(0,3).join(', ')} — common in phishing but not conclusive alone.`);

  const fails = C.filter(c => c.status === 'fail').length;
  const warns = C.filter(c => c.status === 'warn').length;
  if(fails === 0 && warns <= 1)
    add('No deception patterns','pass',0,'No structural tricks, impersonation or cloaking detected in this link.');

  const score = Math.max(0, Math.min(100, 100 - C.reduce((a, c) => a + c.pts, 0)));
  let v;
  if(score >= 85)      v = {cls:'safe',   t:'LIKELY REAL',                m:'No meaningful red flags found. Standard caution still applies — make sure the name matches what you expected.'};
  else if(score >= 65) v = {cls:'caution',t:'PROBABLY REAL — STAY ALERT', m:'Mostly clean, but a couple of details deserve a second look before you type anything sensitive.'};
  else if(score >= 40) v = {cls:'warn',   t:'SUSPICIOUS',                 m:'Several phishing tells are present. Do not log in or enter payment details on this link.'};
  else                 v = {cls:'danger', t:'LIKELY FAKE — DO NOT TRUST', m:'This link shows strong phishing / malware traits. Close it and delete the message that sent it.'};

  const topFails = C.filter(c => c.status === 'fail');
  const topWarns = C.filter(c => c.status === 'warn');
  let plain;
  if(v.cls === 'danger')      plain = 'This link behaves like a fake. ' + topFails.slice(0,2).map(f => f.msg).join(' ');
  else if(v.cls === 'warn')   plain = 'We can\u2019t call this safe. ' + (topFails[0] ? topFails[0].msg : topWarns[0].msg) + ' ' + (topWarns[0] && topFails[0] ? topWarns[0].msg : '');
  else if(v.cls === 'caution')plain = 'Nothing dangerous, but keep your eyes open. ' + topWarns.slice(0,2).map(w => w.msg).join(' ');
  else                        plain = 'The structure is clean: proper encryption, honest domain, no disguise tricks. Safe to proceed with normal care.';

  return {u, raw:s, checks:C, score, v, plain, base, labels, tld, baseCount, isIP, prepended};
}

/* ============================================================
   UI — scanning flow, rendering, history
   ============================================================ */
let scanning = false;
const history = [];
const STEPS = ['Parsing link structure…','Splitting domain anatomy…','Matching impersonation signatures…','Scanning cloaking tricks…','Scoring risk model…'];

async function runScan(raw){
  if(scanning) return;

  const input = $('#url');
  if(!raw || !raw.trim()){
    const box = $('#console');
    box.classList.remove('shake'); void box.offsetWidth; box.classList.add('shake');
    input.focus();
    return;
  }

  scanning = true;
  const btn = $('#scanBtn');
  btn.disabled = true;
  btn.innerHTML = 'SCANNING…';
  input.value = raw;

  const bar = $('#bar'), log = $('#scanlog');
  bar.style.width = '0%'; log.textContent = '';
  for(let i = 0; i < STEPS.length; i++){
    log.textContent = '▸ ' + STEPS[i];
    bar.style.width = ((i + 1) / STEPS.length * 100) + '%';
    await sleep(300);
  }
  log.textContent = '▸ analysis complete.';

  const res = analyze(raw);
  const out = $('#results');
  out.classList.add('show');

  if(!res || res.invalid) renderInvalid();
  else { render(res); pushHistory(res); }

  scanning = false;
  btn.disabled = false;
  btn.innerHTML = 'SCAN <span>→</span>';
  out.scrollIntoView({behavior:'smooth', block:'start'});
}

function renderInvalid(){
  $('#verdictPanel').className = 'panel verdict-panel v-danger';
  const stamp = $('#stamp');
  stamp.style.animation = 'none'; void stamp.offsetWidth; stamp.style.animation = '';
  stamp.textContent = 'NOT A VALID LINK';
  $('#scoreNum').textContent = '—';
  $('#arc').style.strokeDashoffset = 415;
  $('#vmsg').textContent = 'That text doesn\u2019t parse as a URL at all. Check for typos, missing dots or stray spaces.';
  $('#plainTxt').textContent = 'We couldn\u2019t even build a web address from this. Treat anything that sent it to you as suspicious.';
  $('#findList').innerHTML = ''; $('#fcount').textContent = '0';
  $('#urlStrip').textContent = ''; $('#anatTable').innerHTML = '';
  ['#vtLink','#gbLink','#usLink'].forEach(id => $(id).href = '#');
  window.__lastReport = 'LINKTRUTH REPORT — invalid input, no URL could be parsed.';
}

function render(r){
  const {score, v} = r;

  $('#verdictPanel').className = 'panel verdict-panel v-' + v.cls;
  const stamp = $('#stamp');
  stamp.style.animation = 'none'; void stamp.offsetWidth; stamp.style.animation = '';
  stamp.textContent = v.t;
  $('#vmsg').textContent = v.m;
  $('#plainTxt').textContent = r.plain;

  const arc = $('#arc');
  arc.style.transition = 'none';
  arc.style.strokeDashoffset = 415;
  void arc.getBoundingClientRect();
  arc.style.transition = '';
  requestAnimationFrame(() => { arc.style.strokeDashoffset = 415 - (415 * score / 100); });
  animateNum($('#scoreNum'), score, 1200);

  const enc = encodeURIComponent(r.raw);
  $('#vtLink').href = 'https://www.virustotal.com/gui/search/' + enc;
  $('#gbLink').href = 'https://transparencyreport.google.com/safe-browsing/search?url=' + enc;
  $('#usLink').href = 'https://urlscan.io/search/#' + enc;

  const sub     = r.labels.slice(0, r.labels.length - r.baseCount);
  const core    = r.labels.slice(r.labels.length - r.baseCount);
  const coreSld = core.slice(0, -1);
  const coreTld = core[core.length - 1];

  let strip = `<span class="u-scheme">${esc(r.u.protocol)}</span><span class="u-sep">//</span>`;
  if(sub.length) strip += `<span class="u-sub">${esc(sub.join('.'))}</span><span class="u-sep">.</span>`;
  strip += `<span class="u-dom">${esc(coreSld.join('.'))}</span><span class="u-sep">.</span><span class="u-tld">${esc(coreTld)}</span>`;
  if(r.u.port) strip += `<span class="u-scheme">:${esc(r.u.port)}</span>`;
  if(r.u.pathname !== '/') strip += `<span class="u-path">${esc(r.u.pathname)}</span>`;
  if(r.u.search) strip += `<span class="u-q">${esc(r.u.search)}</span>`;
  if(r.u.hash)   strip += `<span class="u-q">${esc(r.u.hash)}</span>`;
  $('#urlStrip').innerHTML = strip;

  const rows = [
    ['PROTOCOL', r.u.protocol + '//' + (r.u.protocol === 'https:' ? 'encrypted ✓' : 'NOT encrypted ✕')],
    ['SUBDOMAIN', sub.length ? sub.join('.') : '— none —'],
    ['TRUE DOMAIN', coreSld.join('.') || '(IP host)'],
    ['ENDING (TLD)', '.' + coreTld],
    ['PORT', r.u.port || 'default'],
    ['PATH', r.u.pathname === '/' ? '—' : r.u.pathname],
    ['QUERY / PARAMS', r.u.search || '—'],
  ];
  $('#anatTable').innerHTML = rows.map(x => `<tr><td>${x[0]}</td><td>${esc(x[1])}</td></tr>`).join('');

  const order = {fail:0, warn:1, info:2, pass:3};
  const sorted = [...r.checks].sort((a, b) => order[a.status] - order[b.status]);
  const icons = {pass:'✓', info:'ℹ', warn:'▲', fail:'✕'};
  const tags  = {pass:'PASS', info:'NOTE', warn:'WARNING', fail:'FAIL'};
  $('#findList').innerHTML = sorted.map((c, i) => `
    <div class="finding f-${c.status}" style="animation-delay:${i * 90}ms">
      <div class="ico">${icons[c.status]}</div>
      <div>
        <div class="fname">${esc(c.name)} <span class="tag">${tags[c.status]}${c.pts ? ' · −' + c.pts + ' PTS' : ''}</span></div>
        <div class="fmsg">${esc(c.msg)}</div>
      </div>
    </div>`).join('');
  $('#fcount').textContent = sorted.length;

  window.__lastReport = buildReport(r);
}

function buildReport(r){
  const lines = [
    `LINKTRUTH REPORT — ${new Date().toLocaleString()}`,
    `URL: ${r.raw}`,
    `VERDICT: ${r.v.t} (trust score ${r.score}/100)`,
    '', 'FINDINGS:'
  ];
  r.checks.forEach(c => lines.push(` [${c.status.toUpperCase()}] ${c.name}: ${c.msg}`));
  lines.push('', 'Note: heuristic opinion only — cross-check with VirusTotal for certainty.');
  return lines.join('\n');
}

function animateNum(el, target, ms){
  const t0 = performance.now();
  (function step(t){
    const p = Math.min(1, (t - t0) / ms);
    el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
    if(p < 1) requestAnimationFrame(step);
  })(t0);
}

function pushHistory(r){
  history.unshift({raw: r.raw, cls: r.v.cls});
  if(history.length > 6) history.pop();
  const colors = {safe:'var(--safe)', caution:'var(--warn)', warn:'var(--orange)', danger:'var(--danger)'};
  $('#recent').innerHTML = '<span class="rlabel">RECENT:</span>' + history.map(h => {
    let label;
    try { label = new URL(h.raw).hostname; } catch(e){ label = h.raw; }
    if(label.length > 30) label = label.slice(0, 28) + '…';
    return `<button class="chip" data-url="${esc(h.raw)}"><span class="hdot" style="background:${colors[h.cls]}"></span>${esc(label)}</button>`;
  }).join('');
}

/* ============================================================
   EVENTS
   ============================================================ */
$('#scanBtn').addEventListener('click', () => runScan($('#url').value));

$('#url').addEventListener('keydown', e => {
  if(e.key === 'Enter') runScan(e.target.value);
  if(e.key === 'Escape'){ e.target.value = ''; }
});

$('#url').addEventListener('paste', () => {
  setTimeout(() => {
    const v = $('#url').value.trim();
    if(v) runScan(v);
  }, 80);
});

document.addEventListener('click', e => {
  const c = e.target.closest('.chip');
  if(c) runScan(c.dataset.url);
});

$('#copyBtn').addEventListener('click', async () => {
  const txt = window.__lastReport || 'No report yet.';
  try { await navigator.clipboard.writeText(txt); }
  catch(e){
    const ta = document.createElement('textarea');
    ta.value = txt; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy'); ta.remove();
  }
  const b = $('#copyBtn');
  b.textContent = '✓ COPIED';
  setTimeout(() => b.textContent = '⧉ COPY REPORT', 1600);
});

/* ============================================================
   AMBIENCE — clock, ticker, live feed, particles, reveals
   ============================================================ */
setInterval(() => {
  $('#clock').textContent = new Date().toLocaleTimeString('en-GB');
}, 1000);

const TIPS = ['PHISHING STARTS WITH A CLICK','A PADLOCK ICON ≠ SAFE','CHECK THE DOMAIN, NOT THE TEXT','HOVER BEFORE YOU CLICK','SHORT LINKS HIDE DESTINATIONS','FREE TLDS (.TK, .ML) TOP ABUSE CHARTS','URGENCY IS A WEAPON','WHEN IN DOUBT, GO DIRECT'];
$('#tickerTrack').innerHTML = TIPS.concat(TIPS).map(t => `<span>◆ <b>${t}</b></span>`).join('');

const FEED = [
  ['sys','▸ engine heartbeat — 20+ checks armed'],
  ['bad','▸ paypa1-secure.tk → FAKE · impersonation: PayPal'],
  ['ok','▸ drive.google.com → REAL · known domain'],
  ['mid','▸ bit.ly/4fQz2xL → SHORTENED · destination hidden'],
  ['bad','▸ netflix-billing.xyz → FAKE · urgency keywords'],
  ['ok','▸ github.com/settings → REAL · encrypted'],
  ['mid','▸ 45.13.220.7/login → SUSPICIOUS · raw IP host'],
  ['bad','▸ app1e-id.verify.gq → FAKE · leet-swap detected'],
  ['ok','▸ outlook.live.com → REAL · known domain'],
  ['sys','▸ tip: the true domain sits just before the first /'],
];
const live = $('#liveLog');
let fi = 0;
function feedLine(){
  const [cls, txt] = FEED[fi % FEED.length];
  fi++;
  const d = document.createElement('div');
  d.className = cls;
  d.textContent = txt;
  d.style.opacity = 0;
  d.style.transition = 'opacity .4s';
  live.appendChild(d);
  requestAnimationFrame(() => d.style.opacity = 1);
  while(live.children.length > 11) live.removeChild(live.firstChild);
}
feedLine(); feedLine(); feedLine();
setInterval(feedLine, 1400);

const cv = $('#fx'), cx = cv.getContext('2d');
let W, H;
function resize(){ W = cv.width = innerWidth; H = cv.height = innerHeight; }
resize();
addEventListener('resize', resize);

const pts = [];
const COUNT = innerWidth < 700 ? 28 : 60;
for(let i = 0; i < COUNT; i++){
  pts.push({
    x: Math.random() * innerWidth, y: Math.random() * innerHeight,
    vx: (Math.random() - .5) * .25, vy: (Math.random() - .5) * .25,
    r: Math.random() * 1.6 + .4,
    c: Math.random() > .7 ? '90,209,255' : '61,220,151'
  });
}
(function loop(){
  cx.clearRect(0, 0, W, H);
  for(const p of pts){
    p.x += p.vx; p.y += p.vy;
    if(p.x < 0) p.x = W; if(p.x > W) p.x = 0;
    if(p.y < 0) p.y = H; if(p.y > H) p.y = 0;
    cx.beginPath();
    cx.arc(p.x, p.y, p.r, 0, 7);
    cx.fillStyle = `rgba(${p.c},.35)`;
    cx.fill();
  }
  requestAnimationFrame(loop);
})();

const io = new IntersectionObserver(es => es.forEach(e => {
  if(e.isIntersecting){ e.target.classList.add('in'); io.unobserve(e.target); }
}), {threshold:.12});
document.querySelectorAll('.reveal').forEach(el => io.observe(el));