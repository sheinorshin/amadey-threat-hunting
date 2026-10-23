/* =========================================================================
   Сайттың жұмыс логикасы: беттер, кейіпкер терезесі, уақыт сызығы,
   сөздік, іздеу және сайыс.
   ========================================================================= */
(function () {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const shuffle = a => { const b = a.slice(); for (let i = b.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [b[i], b[j]] = [b[j], b[i]]; } return b; };
  const pick = a => a[Math.floor(Math.random() * a.length)];
  const store = {
    get(k, d) { try { const v = localStorage.getItem('ka7.' + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem('ka7.' + k, JSON.stringify(v)); } catch (e) { /* сақтау мүмкін емес */ } }
  };

  const B = window.BOOK, CH = window.CHAPTERS, TP = window.TOPICS, AU = window.AUTHORS, CR = window.CHARACTERS;
  const TERMS = window.TERMS, WORDS = window.WORDS, TL = window.TIMELINE, QZ = window.QUIZ, RG = window.REGIONS, CITIES = window.CITIES;
  const EM = window.EMBLEMS, UI = window.UI;

  /* ---------- Деректер картасы ---------- */
  const TMAP = {}, AMAP = {}, CMAP = {}, TERMMAP = {};
  TP.forEach(t => { TMAP[t.id] = t; });
  AU.forEach(a => { AMAP[a.id] = a; });
  CR.forEach(c => { CMAP[c.id] = c; });
  TERMS.forEach(([t, d, ex]) => { TERMMAP[t.toLowerCase()] = { t, d, ex, topics: [] }; });
  TP.forEach(t => (t.terms || []).forEach(k => {
    const g = TERMMAP[k.toLowerCase()];
    if (g) { if (!g.topics.includes(t.id)) g.topics.push(t.id); } else console.warn('Термин табылмады:', k, t.id);
  }));
  TP.forEach(t => (t.chars || []).forEach(c => { if (!CMAP[c]) console.warn('Кейіпкер табылмады:', c, t.id); }));
  CR.forEach(c => { if (!TMAP[c.w]) console.warn('Шығарма табылмады:', c.w, c.id); });
  WORDS.forEach(w => { if (!TMAP[w[2]]) console.warn('Сөздің тақырыбы табылмады:', w); });
  const ORDER = TP.map(t => t.id);
  const WORKS = TP.filter(t => t.kind !== 'topic');
  const chOf = n => CH.find(c => c.n === n);
  const cvar = n => `var(--c${n})`;
  const tColor = t => (t ? cvar(t.ch) : 'var(--gold)');
  const aTopic = a => TMAP[(a.tb || [])[0]];
  const aColor = a => tColor(aTopic(a));
  const pages = t => (t.p ? (t.p[0] === t.p[1] ? `${t.p[0]}-бет` : `${t.p[0]}–${t.p[1]}-беттер`) : '');
  const initials = n => {
    const w = n.replace(/\(.*?\)/g, '').trim().split(/[\s-]+/).filter(x => /^[А-ЯӘҒҚҢӨҰҮҺІЁA-Z]/.test(x));
    return (w.length ? w.slice(0, 2).map(x => x[0]).join('') : n[0]).toUpperCase();
  };
  const ini = (name, color, cls = '') => `<span class="ini ${cls}" style="--c:${color}" aria-hidden="true">${esc(initials(name))}</span>`;
  const emb = (t, cls = '') => `<span class="emb ${cls}" style="--c:${tColor(t)}" aria-hidden="true">${EM[t.icon] || EM.book}</span>`;
  const workAuthor = t => (t.author ? AMAP[t.author] : null);
  const workBy = t => { const a = workAuthor(t); return a ? a.n : (t.byline || t.folk || ''); };
  const ORN = window.ORNAMENT;
  const dc = s => (/^[A-Za-zА-Яа-яӘәҒғҚқҢңӨөҰұҮүҺһІіЁё]/.test(String(s || '')) ? ' dc' : '');

  /* ---------- Оқылған шығармалар ---------- */
  let READ = new Set(store.get('read', []));
  const saveRead = () => store.set('read', Array.from(READ));

  /* ---------- Түс тақырыбы ---------- */
  const root = document.documentElement;
  const isDark = () => { const t = root.getAttribute('data-theme'); return t ? t === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches; };
  function applyTheme(t) {
    if (t) root.setAttribute('data-theme', t); else root.removeAttribute('data-theme');
    const b = $('#themeBtn');
    if (b) { b.innerHTML = isDark() ? UI.sun : UI.moon; b.setAttribute('aria-label', isDark() ? 'Жарық түске ауысу' : 'Қараңғы түске ауысу'); }
  }
  function toggleTheme() { const next = isDark() ? 'light' : 'dark'; store.set('theme', next); applyTheme(next); }
  applyTheme(store.get('theme', null));
  try { window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => applyTheme(root.getAttribute('data-theme'))); } catch (e) { /* ескі браузер */ }

  /* ---------- Ортақ бөлшектер ---------- */
  const secH = (title, more) => `<div class="sec-h"><h2>${title}</h2>${more || ''}</div>`;
  const block = (title, inner, k) => `<section class="block"><h2>${title}${k ? `<span class="k">${k}</span>` : ''}</h2>${inner}</section>`;
  const paras = arr => (arr || []).map(p => `<p>${esc(p)}</p>`).join('');
  const quoteBlock = q => (q ? `<figure class="quote"><p>«${esc(q.text)}»</p><cite>— ${esc(q.by)}</cite></figure>` : '');
  const termCard = name => {
    const g = TERMMAP[name.toLowerCase()];
    if (!g) return '';
    return `<div class="term card"><b>${esc(g.t)}</b><p>${esc(g.d)}</p>${g.ex ? `<p class="ex">${esc(g.ex)}</p>` : ''}</div>`;
  };
  const wordsList = list => `<dl class="words">${list.map(w => `<div><dt>${esc(w[0])}</dt><dd>${esc(w[1])}</dd></div>`).join('')}</dl>`;
  const charCards = ids => `<div class="cgrid">${ids.map(id => CMAP[id]).filter(Boolean).map(c => {
    const t = TMAP[c.w];
    return `<button type="button" class="ccard" data-char="${c.id}" style="--c:${tColor(t)}">${ini(c.n, tColor(t))}<span><b>${esc(c.n)}</b><small>${esc(c.role)}${c.real ? ' · тарихи тұлға' : ''}</small><span class="d">${esc(c.d)}</span></span></button>`;
  }).join('')}</div>`;

  /* =====================================================================
     Басты бет
     ===================================================================== */
  function quoteOfDay() {
    const pool = [];
    TP.forEach(t => { if (t.quote) pool.push([t.quote.text, t.quote.by, t.id]); (t.proverbs || []).forEach(p => pool.push([p, 'Сөздің көркі — мақал', t.id])); });
    AU.forEach(a => { if (a.own) pool.push([a.own, a.n, 'a:' + a.id]); });
    const day = Math.floor(Date.now() / 864e5);
    return pool[day % pool.length];
  }
  function shelf() {
    let html = '', lastCh = 0;
    WORKS.forEach(t => {
      if (t.ch !== lastCh) { lastCh = t.ch; const ch = chOf(t.ch); html += `<a class="book-end" href="#c-${ch.n}" style="--c:${cvar(ch.n)}" title="${esc(ch.r + ' тарау: ' + ch.t)}">${ch.r}</a>`; }
      const span = t.p[1] - t.p[0];
      const h = Math.round(196 + Math.min(span, 28) * 3.6);
      const a = workAuthor(t);
      const au = a ? a.short : (t.kind === 'article' ? 'мақала' : 'халық жыры');
      const title = t.t.replace(/[«»]/g, '');
      html += `<a class="spine" href="#t-${t.id}" style="--c:${cvar(t.ch)};height:${h}px" aria-label="${esc(t.full || t.t)}, ${esc(workBy(t))}${READ.has(t.id) ? ', оқылды' : ''}"><span class="pg">${t.p[0]}</span><span class="tt">${esc(title)}</span><span class="au">${esc(au)}</span>${READ.has(t.id) ? `<span class="ok">${UI.check}</span>` : ''}</a>`;
    });
    return html;
  }
  function home() {
    const q = quoteOfDay();
    const qref = q[2].startsWith('a:') ? `#a-${q[2].slice(2)}` : `#t-${q[2]}`;
    const readN = WORKS.filter(t => READ.has(t.id)).length;
    return `
    <section class="hero wrap">
      <div>
        <span class="eyebrow">7-сынып · оқулыққа серік сайт</span>
        <h1>Қазақ <em>әдебиеті</em></h1>
        <p class="lead">Оқулықтағы шығармалар бір сөреде: қысқаша мазмұны, оқиға желісі, кейіпкерлері, ақын-жазушылардың өмірі, сөздік пен сайыс.</p>
        <div class="stats">
          <a href="#works"><b>6</b>тарау</a>
          <a href="#works"><b>${WORKS.length}</b>шығарма</a>
          <a href="#authors"><b>${AU.length}</b>ақын-жазушы</a>
          <a href="#characters"><b>${CR.length}</b>кейіпкер</a>
          <a href="#glossary"><b>${WORDS.length}</b>сөз</a>
        </div>
      </div>
      <div class="bookcard card">
        <span class="eyebrow">Оқулық туралы</span>
        <div class="row"><span>Атауы</span><b>«${esc(B.title)}», ${esc(B.grade)}</b></div>
        <div class="row"><span>Авторлары</span><b>${B.authors.map(esc).join(', ')}</b></div>
        <div class="row"><span>Баспасы</span><span>${esc(B.pub)}</span></div>
        <div class="row"><span>Көлемі</span><span>${B.pages} бет, 6 тарау</span></div>
      </div>
    </section>

    <section class="sec wrap shelf-wrap" aria-labelledby="shelf-h">
      <div class="sec-h"><h2 id="shelf-h">Кітап сөресі</h2>
        <div class="progress" title="Оқылған шығармалар"><span>Оқылды: ${readN}/${WORKS.length}</span><span class="bar"><i style="width:${Math.round(readN / WORKS.length * 100)}%"></i></span></div>
      </div>
      <p class="muted ui" style="font-size:15px">Әр кітап — оқулықтағы бір шығарма. Кітаптың биіктігі оқулықтағы бет санына сай, үстіндегі сан — басталатын беті.</p>
      <div class="shelf-scroll"><div class="shelf">${shelf()}</div></div>
      <div class="shelf-legend">${CH.slice(0, 5).map(c => `<span style="--c:${cvar(c.n)}"><i></i>${c.r}. ${esc(c.t)}</span>`).join('')}</div>
    </section>

    <section class="sec wrap">
      ${secH('Тараулар', '<a class="more" href="#works">Толық мазмұны →</a>')}
      <div class="chgrid">${CH.map(c => {
        const ts = TP.filter(t => t.ch === c.n);
        return `<a class="chcard card" href="#c-${c.n}" style="--c:${cvar(c.n)}"><span class="rn">${c.r}</span><h3>${esc(c.t)}</h3><ul>${ts.map(t => `<li>${esc(t.t)}</li>`).join('')}</ul></a>`;
      }).join('')}</div>
    </section>

    <section class="sec wrap">
      <div class="divider">${ORN}</div>
      <figure class="qcard"><span class="eyebrow">Күннің сөзі</span><blockquote>«${esc(q[0])}»</blockquote><cite>— ${esc(q[1])} · <a href="${qref}">оқу</a></cite></figure>
      <div class="feat">
        <a class="card" href="#characters">${UI.people}<b>Кейіпкерлер</b><span>${CR.length} кейіпкердің мінезі, рөлі, айтқан сөзі.</span></a>
        <a class="card" href="#timeline">${UI.clock}<b>Уақыт сызығы</b><span>Күлтегін тасынан тәуелсіздік жырына дейін.</span></a>
        <a class="card" href="#glossary">${UI.dict}<b>Сөздік</b><span>${TERMS.length} термин және «Сөзмаржандағы» ${WORDS.length} сөз.</span></a>
        <a class="card" href="#quiz">${UI.star}<b>Сайыс</b><span>Шығарма, кейіпкер, термин бойынша тест.</span></a>
      </div>
    </section>`;
  }

  /* =====================================================================
     Мазмұны (шығармалар)
     ===================================================================== */
  function works() {
    return `<div class="wrap">
      <header class="ph"><span class="eyebrow">Оқулықтың мазмұны</span><h1>Шығармалар</h1>
      <p class="lead">Тақырыптар оқулықтағы ретімен берілді. Оң жақтағы сан — оқулықтағы беті.</p></header>
      <div class="toc">${CH.map(c => `
        <section class="toc-ch" style="--c:${cvar(c.n)}">
          <a class="toc-head" href="#c-${c.n}"><span class="rn">${c.r}</span><h2>${esc(c.t)}</h2><span class="pg">${c.p}</span></a>
          <ol class="toc-list">${TP.filter(t => t.ch === c.n).map(t => `<li><a href="#t-${t.id}"><span class="tl">${esc(t.full || t.t)}<small>${esc(workBy(t) || (t.kind === 'topic' ? 'Шолу тақырыбы' : ''))}</small></span><span class="dots"></span>${READ.has(t.id) ? `<span class="rd" title="Оқылды">${UI.check}</span>` : ''}<span class="pg">${t.p[0]}</span></a></li>`).join('')}</ol>
        </section>`).join('')}
      </div></div>`;
  }

  /* =====================================================================
     Тарау беті
     ===================================================================== */
  function chapterPage(c) {
    const ts = TP.filter(t => t.ch === c.n);
    const prev = chOf(c.n - 1), next = chOf(c.n + 1);
    return `<div class="wrap">
      <div class="chhero" style="--c:${cvar(c.n)}"><span class="big">${c.r}</span>
        <div><span class="eyebrow">${c.r} тарау · ${c.p}-бет</span><h1 style="font-size:clamp(32px,5.6vw,56px);margin-top:8px">${esc(c.t)}</h1><p class="lead" style="margin-top:12px">${esc(c.intro)}</p></div>
      </div>
      <section class="sec" style="--c:${cvar(c.n)}">${secH('Бұл тарауда сендер')}<ul class="goals">${c.goals.map(g => `<li>${esc(g)}</li>`).join('')}</ul></section>
      <section class="sec">${secH('Тақырыптар')}
        <div class="tcards">${ts.map(t => `<a class="tcard card" href="#t-${t.id}" style="--c:${tColor(t)}">${emb(t)}<span><h3>${esc(t.t)}</h3><span class="meta">${esc([workBy(t), t.genre || (t.kind === 'topic' ? 'Шолу тақырыбы' : ''), pages(t)].filter(Boolean).join(' · '))}</span><p>${esc(t.about || t.lead || '')}</p></span></a>`).join('')}</div>
      </section>
      <nav class="pn" aria-label="Тараулар">
        ${prev ? `<a class="card" href="#c-${prev.n}"><small>← Алдыңғы тарау</small><b>${prev.r}. ${esc(prev.t)}</b></a>` : '<span></span>'}
        ${next ? `<a class="card nx" href="#c-${next.n}"><small>Келесі тарау →</small><b>${next.r}. ${esc(next.t)}</b></a>` : '<span></span>'}
      </nav></div>`;
  }

  /* =====================================================================
     Тақырып / шығарма беті
     ===================================================================== */
  function topicPage(t) {
    const ch = chOf(t.ch), c = tColor(t), a = workAuthor(t);
    const i = ORDER.indexOf(t.id), prev = TP[i - 1], next = TP[i + 1];
    const isWork = t.kind !== 'topic';
    let by = '';
    if (t.kind === 'article') by = `Мақала авторы: ${esc(t.byline)} · ${esc(t.paper)}`;
    else if (a) by = `<a href="#a-${a.id}">${esc(a.n)}</a> · ${esc(t.genre)}`;
    else if (t.folk) by = `${esc(t.folk)} · ${esc(t.genre)}`;
    const rows = [];
    if (t.kind === 'article') { rows.push(['Авторы', esc(t.byline)], ['Басылым', esc(t.paper)]); }
    else if (a) rows.push(['Авторы', `<a href="#a-${a.id}">${esc(a.n)}</a>`]);
    else if (t.folk) rows.push(['Авторы', esc(t.folk)]);
    if (t.translator) rows.push(['Аударған', esc(t.translator)]);
    if (t.genre) rows.push(['Жанры', esc(t.genre)]);
    if (t.when) rows.push(['Уақыты', esc(t.when)]);
    if (t.place) rows.push(['Мекені', esc(t.place)]);
    rows.push(['Оқулықта', esc(pages(t))]);
    if (t.chars && t.chars.length) rows.push(['Кейіпкерлері', `<a href="#chars-${t.id}" data-jump="chars">${t.chars.length} кейіпкер</a>`]);
    const words = WORDS.filter(w => w[2] === t.id);
    const read = READ.has(t.id);

    const blocks = [];
    if (isWork) {
      blocks.push(block('Шығарма туралы', `<div class="prose${dc(t.about)}" style="--c:${c}"><p>${esc(t.about)}</p>${t.structure ? `<p>${esc(t.structure)}</p>` : ''}</div>`));
      if (t.plot) {
        const g = (t.genre || '').toLowerCase();
        const h = t.kind === 'article' ? 'Мақала желісі' : (/^(толғау|өлең)/.test(g) ? 'Өлең желісі' : 'Оқиға желісі');
        blocks.push(block(h, `<ol class="plot" style="--c:${c}">${t.plot.map(([b, p]) => `<li><div><b>${esc(b)}</b><p>${esc(p)}</p></div></li>`).join('')}</ol>`));
      }
      blocks.push(block('Тақырыбы мен идеясы', `<div class="ti"><div class="card"><h3>Тақырыбы</h3><p>${esc(t.theme)}</p></div><div class="card"><h3>Идеясы</h3><p>${esc(t.idea)}</p></div></div>${t.lyric ? `<p class="note" style="margin-top:12px">${esc(t.lyric)}</p>` : ''}`));
      if (t.chars && t.chars.length) blocks.push(`<div id="chars-${t.id}">${block('Кейіпкерлер', charCards(t.chars))}</div>`);
    } else {
      blocks.push(block('Тақырып туралы', `<div class="prose${dc((t.body || [])[0])}" style="--c:${c}">${paras(t.body)}</div>`));
      if (t.list) blocks.push(block(esc(t.list.h), `<ul class="facts">${t.list.items.map(x => `<li><span>${esc(x)}</span></li>`).join('')}</ul>`));
      if (t.examples) blocks.push(block('Үлгілері', `<div class="chips">${t.examples.map(x => `<span class="chip">${esc(x)}</span>`).join('')}</div>`));
      if (t.runes) blocks.push(block('Тастағы алғашқы сөздер', `<div class="runes">${t.runes.map(([r, k]) => `<div class="rune card"><b lang="otk">${r}</b><span>${esc(k)}</span></div>`).join('')}</div><p class="note" style="margin-top:12px">Көне түркі жазуы оңнан солға қарай оқылады.</p>`));
      if (t.periods) blocks.push(block('Ежелгі дәуір әдебиетінің кезеңдері', `<div class="tbl-wrap"><table class="periods"><tbody>${t.periods.map(([y, n, w]) => `<tr><th>${esc(y)}</th><td><b>${esc(n)}</b><span>${esc(w)}</span></td></tr>`).join('')}</tbody></table></div>`));
      if (t.regions) blocks.push(block('Қазақстан өңірлері', `<div class="regions">${RG.map(r => `<div class="region card"><h3>${esc(r.zone)}</h3><ul>${r.items.map(([o, cc]) => `<li>${esc(o)}<span>${esc(cc)}</span></li>`).join('')}</ul><p class="w"><b>Ақын-жазушылар:</b> ${r.writers.map(esc).join(', ')}</p><div class="chips">${r.works.map(id => TMAP[id]).filter(Boolean).map(x => `<a class="chip" href="#t-${x.id}">${esc(x.t)}</a>`).join('')}</div></div>`).join('')}<div class="region card"><h3>Республикалық маңызы бар қалалар</h3><ul>${CITIES.map(([n, d]) => `<li>${esc(n)}<span>${esc(d)}</span></li>`).join('')}</ul></div></div>`));
    }
    if (t.excerpt) {
      const ex = t.excerpt;
      blocks.push(block('Үзінді', `<figure class="verse" style="--c:${c}"><div class="vh">${esc(ex.h)}</div><div class="vl${ex.prose ? ' prose-ex' : ''}">${ex.lines.map(l => `<span>${esc(l)}</span>`).join('')}</div>${ex.note ? `<div class="vn">${esc(ex.note)}</div>` : ''}</figure>`));
    }
    if ((t.facts && t.facts.length) || t.quote) {
      blocks.push(block('Бағалы дерек', `${t.facts ? `<ul class="facts">${t.facts.map(f => `<li><span>${esc(f)}</span></li>`).join('')}</ul>` : ''}${t.quote ? `<div style="margin-top:18px"><div class="eyebrow" style="margin-bottom:8px">Зерделі сөз</div>${quoteBlock(t.quote)}</div>` : ''}`));
    }
    if (t.proverbs) blocks.push(block('Сөздің көркі — мақал', `<div class="proverbs">${t.proverbs.map(p => `<p>${esc(p)}</p>`).join('')}</div>`));
    if (t.terms && t.terms.length) blocks.push(block('Әдебиет теориясы', `<div class="terms">${t.terms.map(termCard).join('')}</div>`));
    if (words.length) blocks.push(block('Сөзмаржан', wordsList(words), words.length + ' сөз'));
    if (t.qs) blocks.push(block('Өзіңді тексер', `<ol class="qs" style="--c:${c}">${t.qs.map(([lv, q]) => `<li><span class="lv">${esc(lv)}</span><span>${esc(q)}</span></li>`).join('')}</ol>`));

    return `<div class="wrap">
      <header class="thero" style="--c:${c}">
        <div><span class="eyebrow"><a href="#c-${ch.n}">${ch.r} тарау · ${esc(ch.t)}</a></span>
          <h1>${esc(t.full && t.kind === 'topic' ? t.full : t.t)}</h1>
          ${by ? `<p class="by">${by}</p>` : ''}${t.lead ? `<p class="lead" style="margin-top:12px">${esc(t.lead)}</p>` : ''}
        </div>
        ${emb(t)}
      </header>
      <div class="tlayout">
        <div class="content">${blocks.join('')}</div>
        <aside class="aside">
          <div class="passport card" style="--c:${c}"><h2>${isWork ? 'Шығарма паспорты' : 'Тақырып паспорты'}</h2><dl>${rows.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join('')}</dl></div>
          <button type="button" class="btn ${read ? 'done' : 'alt'}" data-read="${t.id}" aria-pressed="${read}">${read ? UI.check + ' Оқылды' : 'Оқыдым деп белгілеу'}</button>
        </aside>
      </div>
      <nav class="pn" aria-label="Тақырыптар">
        ${prev ? `<a class="card" href="#t-${prev.id}"><small>← Алдыңғы</small><b>${esc(prev.t)}</b></a>` : '<span></span>'}
        ${next ? `<a class="card nx" href="#t-${next.id}"><small>Келесі →</small><b>${esc(next.t)}</b></a>` : '<span></span>'}
      </nav></div>`;
  }

  /* =====================================================================
     Ақын-жазушылар
     ===================================================================== */
  const AUTH_SORTED = AU.slice().sort((x, y) => x.by - y.by);
  function authors() {
    return `<div class="wrap">
      <header class="ph"><span class="eyebrow">Оқулықтағы шығармалардың авторлары</span><h1>Ақын-жазушылар</h1>
      <p class="lead">Ежелгі түркі ақынынан бүгінгі қаламгерлерге дейін — өмір сүрген уақыты бойынша.</p></header>
      <div class="agrid">${AUTH_SORTED.map(a => { const t = aTopic(a); return `<a class="acard card" href="#a-${a.id}" style="--c:${aColor(a)}">${ini(a.n, aColor(a))}<span><b>${esc(a.n)}</b><span class="y">${esc(a.y)}</span><span class="r">${esc(a.role)}</span>${t ? `<span class="w">${esc(t.t)}</span>` : ''}</span></a>`; }).join('')}</div>
      <p class="note" style="margin-top:22px">«Қыз Жібек» — халық жыры, оның нақты авторы жоқ. IV тараудағы мақалалардың авторлары әр шығарманың бетінде көрсетілген.</p>
    </div>`;
  }
  function authorPage(a) {
    const c = aColor(a), i = AUTH_SORTED.indexOf(a), prev = AUTH_SORTED[i - 1], next = AUTH_SORTED[i + 1];
    const tb = (a.tb || []).map(id => TMAP[id]).filter(Boolean);
    const tbTitles = tb.map(t => t.t.replace(/[«»]/g, ''));
    return `<div class="wrap">
      <header class="ahero" style="--c:${c}">${ini(a.n, c)}
        <div><span class="eyebrow"><a href="#authors">Ақын-жазушылар</a></span><h1 style="margin-top:8px">${esc(a.n)}</h1><p class="y">${esc(a.y)}</p><p class="r">${esc(a.role)}${a.born && a.born !== '—' ? ' · ' + esc(a.born) : ''}</p></div>
      </header>
      <div class="tlayout">
        <div class="content">
          ${block('Өмірі мен шығармашылығы', `<div class="prose${dc(a.bio)}" style="--c:${c}"><p>${esc(a.bio)}</p></div>`)}
          ${a.life && a.life.length ? block('Өмір белестері', `<ol class="life" style="--c:${c}">${a.life.map(([y, x]) => `<li><b>${esc(y)}</b><span>${esc(x)}</span></li>`).join('')}</ol>`) : ''}
          ${block('Шығармалары', `<div class="chips">${a.works.map(w => { const t = tb.find((x, k) => w.replace(/[«»]/g, '').startsWith(tbTitles[k])); return t ? `<a class="chip" href="#t-${t.id}" style="background:var(--accent-soft);color:var(--accent)">${esc(w)}</a>` : `<span class="chip">${esc(w)}</span>`; }).join('')}</div>`)}
          ${a.quote ? block('Зерделі сөз', quoteBlock(a.quote)) : ''}
          ${a.own ? block('Даналық ойдан дән ізде', quoteBlock({ text: a.own, by: a.n })) : ''}
        </div>
        <aside class="aside">
          ${tb.map(t => `<a class="tcard card" href="#t-${t.id}" style="--c:${tColor(t)}">${emb(t)}<span><span class="eyebrow">Оқулықта</span><h3>${esc(t.t)}</h3><span class="meta">${esc([t.genre, pages(t)].filter(Boolean).join(' · '))}</span></span></a>`).join('')}
          <div class="passport card"><h2>Қысқаша</h2><dl>
            <div><dt>Жылдары</dt><dd>${esc(a.y)}</dd></div>
            ${a.born && a.born !== '—' ? `<div><dt>Туған жері</dt><dd>${esc(a.born)}</dd></div>` : ''}
            <div><dt>Кім</dt><dd>${esc(a.role)}</dd></div></dl></div>
        </aside>
      </div>
      <nav class="pn" aria-label="Ақын-жазушылар">
        ${prev ? `<a class="card" href="#a-${prev.id}"><small>← Алдыңғы</small><b>${esc(prev.n)}</b></a>` : '<span></span>'}
        ${next ? `<a class="card nx" href="#a-${next.id}"><small>Келесі →</small><b>${esc(next.n)}</b></a>` : '<span></span>'}
      </nav></div>`;
  }

  /* =====================================================================
     Кейіпкерлер
     ===================================================================== */
  let charState = { ch: 0, q: '' };
  function charGroups() {
    const q = charState.q.trim().toLowerCase();
    const groups = WORKS.filter(t => t.chars && t.chars.length && (!charState.ch || t.ch === charState.ch)).map(t => {
      const list = t.chars.map(id => CMAP[id]).filter(c => c && (!q || c.n.toLowerCase().includes(q) || c.d.toLowerCase().includes(q)));
      return list.length ? `<section class="wgroup"><h3><a href="#t-${t.id}">${esc(t.t)}</a> <span class="muted ui" style="font-size:14px">${esc(workBy(t))}</span></h3>${charCards(list.map(c => c.id))}</section>` : '';
    }).join('');
    return groups || '<p class="empty">Ешкім табылмады. Басқа сөзбен іздеп көріңіз.</p>';
  }
  function characters() {
    const chs = CH.filter(c => TP.some(t => t.ch === c.n && t.chars && t.chars.length));
    return `<div class="wrap">
      <header class="ph"><span class="eyebrow">${CR.length} кейіпкер</span><h1>Кейіпкерлер</h1>
      <p class="lead">Кейіпкерді басып, оның мінезін, рөлін және айтқан сөзін ашыңыз.</p></header>
      <div class="filters" role="group" aria-label="Тарау бойынша сүзу">
        <button type="button" data-chf="0" aria-pressed="${charState.ch === 0}">Барлығы</button>
        ${chs.map(c => `<button type="button" data-chf="${c.n}" aria-pressed="${charState.ch === c.n}">${c.r} тарау</button>`).join('')}
      </div>
      <label class="searchbox">${UI.search}<span class="sr">Кейіпкер іздеу</span><input id="charQ" type="search" placeholder="Кейіпкер іздеу: Төлеген, Серік…" value="${esc(charState.q)}" autocomplete="off"></label>
      <div id="charList">${charGroups()}</div></div>`;
  }
  function charactersPost() {
    const inp = $('#charQ'), list = $('#charList');
    inp.addEventListener('input', () => { charState.q = inp.value; list.innerHTML = charGroups(); });
    $$('[data-chf]').forEach(b => b.addEventListener('click', () => {
      charState.ch = +b.dataset.chf; $$('[data-chf]').forEach(x => x.setAttribute('aria-pressed', String(x === b))); list.innerHTML = charGroups();
    }));
  }
  function charModal(id) {
    const c = CMAP[id]; if (!c) return;
    const t = TMAP[c.w], col = tColor(t), a = workAuthor(t);
    const others = CR.filter(x => x.w === c.w && x.id !== c.id);
    const tags = [`<span class="tag main" style="--c:${col}">${esc(c.role)}</span>`];
    if (c.real) tags.push('<span class="tag real">Тарихи тұлға</span>');
    if (c.bad) tags.push('<span class="tag bad">Жағымсыз кейіпкер</span>');
    openModal(`<div class="head" style="--c:${col}">${ini(c.n, col)}<div><span class="eyebrow">${esc(t ? t.t : '')}</span><h2 id="mtitle">${esc(c.n)}</h2></div></div>
      <p class="sub">${t ? `<a href="#t-${t.id}">${esc(t.full || t.t)}</a>` : ''}${a ? ` · <a href="#a-${a.id}">${esc(a.n)}</a>` : ''}${c.y ? ` · ${esc(c.y)}` : ''}</p>
      <div class="body" style="--c:${col}">
        <div class="chips">${tags.join('')}</div>
        <p>${esc(c.d)}</p>
        ${c.traits && c.traits.length ? `<div><div class="eyebrow" style="margin-bottom:8px">Мінезі</div><div class="chips">${c.traits.map(x => `<span class="chip">${esc(x)}</span>`).join('')}</div></div>` : ''}
        ${c.say ? `<p class="say">${esc(c.say)}</p>` : ''}
        ${others.length ? `<div><div class="eyebrow" style="margin-bottom:8px">Осы шығармада тағы</div><div class="chips">${others.map(o => `<button type="button" class="chip" data-char="${o.id}">${esc(o.n)}</button>`).join('')}</div></div>` : ''}
      </div>`);
  }

  /* =====================================================================
     Уақыт сызығы
     ===================================================================== */
  let tlKind = 'all';
  const ROMAN = ['', 'I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII', 'IX', 'X', 'XI', 'XII', 'XIII', 'XIV', 'XV', 'XVI', 'XVII', 'XVIII', 'XIX', 'XX', 'XXI'];
  function refInfo(ref) {
    if (!ref) return null;
    const [k, id] = ref.split(':');
    if (k === 't' && TMAP[id]) return { href: '#t-' + id, label: TMAP[id].t, color: tColor(TMAP[id]) };
    if (k === 'a' && AMAP[id]) return { href: '#a-' + id, label: AMAP[id].n, color: aColor(AMAP[id]) };
    return null;
  }
  function tlList() {
    let last = 0, html = '';
    TL.filter(e => tlKind === 'all' || e.kind === tlKind).forEach(e => {
      const cent = Math.floor((e.y - 1) / 100) + 1;
      if (cent !== last) { last = cent; html += `<li class="cent"><span class="yr">${ROMAN[cent] || cent}</span><span></span><span class="tx"><span class="sr">${ROMAN[cent] || cent} ғасыр</span></span></li>`; }
      const r = refInfo(e.ref);
      html += `<li class="${e.kind}" style="--c:${r ? r.color : 'var(--ink-3)'}"><span class="yr">${esc(e.label)}</span><span class="dot"></span><span class="tx"><b>${esc(e.t)}</b>${e.d ? `<p>${esc(e.d)}</p>` : ''}${r ? `<a href="${r.href}">${esc(r.label)} →</a>` : ''}</span></li>`;
    });
    return html;
  }
  function timeline() {
    const f = [['all', 'Барлығы'], ['work', 'Шығармалар'], ['life', 'Ақын-жазушылар'], ['event', 'Тарихи оқиғалар']];
    return `<div class="wrap">
      <header class="ph"><span class="eyebrow">VIII ғасырдан бүгінге дейін</span><h1>Уақыт сызығы</h1>
      <p class="lead">Шығармалардың жазылған, оқиғалары өткен уақыты және ақын-жазушылардың өмір белестері. Түсі — тарауының түсі.</p></header>
      <div class="filters" role="group" aria-label="Түрі бойынша сүзу">${f.map(([k, l]) => `<button type="button" data-tlf="${k}" aria-pressed="${tlKind === k}">${l}</button>`).join('')}</div>
      <ol class="tl" id="tlList">${tlList()}</ol></div>`;
  }
  function timelinePost() {
    $$('[data-tlf]').forEach(b => b.addEventListener('click', () => {
      tlKind = b.dataset.tlf; $$('[data-tlf]').forEach(x => x.setAttribute('aria-pressed', String(x === b))); $('#tlList').innerHTML = tlList();
    }));
  }

  /* =====================================================================
     Сөздік
     ===================================================================== */
  let glTab = 'terms', glQ = '';
  const norm = s => String(s).toLowerCase().replace(/[«»"()]/g, '');
  function glTerms() {
    const q = norm(glQ.trim());
    const list = TERMS.filter(([t, d]) => !q || norm(t).includes(q) || norm(d).includes(q));
    if (!list.length) return '<p class="empty">Ештеңе табылмады.</p>';
    return `<div class="terms">${list.map(([t]) => {
      const g = TERMMAP[t.toLowerCase()];
      return `<div class="term card"><b>${esc(g.t)}</b><p>${esc(g.d)}</p>${g.ex ? `<p class="ex">${esc(g.ex)}</p>` : ''}${g.topics.length ? `<div class="chips in">${g.topics.map(id => `<a class="chip" href="#t-${id}">${esc(TMAP[id].t)}</a>`).join('')}</div>` : ''}</div>`;
    }).join('')}</div>`;
  }
  function glWords() {
    const q = norm(glQ.trim());
    const html = TP.map(t => {
      const list = WORDS.filter(w => w[2] === t.id && (!q || norm(w[0]).includes(q) || norm(w[1]).includes(q)));
      return list.length ? `<section class="wgroup"><h3><a href="#t-${t.id}">${esc(t.t)}</a></h3>${wordsList(list)}</section>` : '';
    }).join('');
    return html || '<p class="empty">Ештеңе табылмады.</p>';
  }
  function glossary() {
    return `<div class="wrap">
      <header class="ph"><span class="eyebrow">Терминдер мен сирек сөздер</span><h1>Сөздік</h1>
      <p class="lead">«Әдебиет теориясы» айдарындағы терминдер және әр шығармадағы «Сөзмаржан» сөздері.</p></header>
      <div class="tabs" role="tablist">
        <button type="button" role="tab" data-gt="terms" aria-selected="${glTab === 'terms'}">Әдебиет теориясы · ${TERMS.length}</button>
        <button type="button" role="tab" data-gt="words" aria-selected="${glTab === 'words'}">Сөзмаржан · ${WORDS.length}</button>
      </div>
      <label class="searchbox">${UI.search}<span class="sr">Сөздіктен іздеу</span><input id="glQ" type="search" placeholder="Іздеу: теңеу, қорамсақ…" value="${esc(glQ)}" autocomplete="off"></label>
      <div id="glList">${glTab === 'terms' ? glTerms() : glWords()}</div></div>`;
  }
  function glossaryPost() {
    const inp = $('#glQ'), list = $('#glList');
    const upd = () => { list.innerHTML = glTab === 'terms' ? glTerms() : glWords(); };
    inp.addEventListener('input', () => { glQ = inp.value; upd(); });
    $$('[data-gt]').forEach(b => b.addEventListener('click', () => {
      glTab = b.dataset.gt; $$('[data-gt]').forEach(x => x.setAttribute('aria-selected', String(x === b))); upd();
    }));
  }

  /* =====================================================================
     Сайыс
     ===================================================================== */
  const MODES = [
    ['mix', 'Аралас сайыс', 'Барлық тақырыптан 10 сұрақ.', UI.shuffle],
    ['works', 'Шығарма мен автор', 'Кім жазды? Қай кезде? Қайда?', UI.books],
    ['chars', 'Кейіпкерлер', 'Кейіпкер қай шығармадан? Бұл кімнің сөзі?', UI.people],
    ['terms', 'Әдебиет теориясы', 'Анықтамасы бойынша терминді тап.', UI.quill],
    ['words', 'Сөзмаржан', 'Сирек сөздің мағынасын тап.', UI.dict]
  ];
  const mk = (q, right, wrong, ref, ctx) => ({ q, a: right, opts: shuffle([right].concat(wrong.slice(0, 3))), ref, ctx });
  const others = (arr, not) => shuffle(Array.from(new Set(arr.filter(x => x !== not))));
  const G = {
    hand() { const [q, o, ref] = pick(QZ); return mk(q, o[0], o.slice(1), ref, TMAP[ref] ? TMAP[ref].t : ''); },
    author() { const t = pick(WORKS.filter(w => w.author)); const r = AMAP[t.author].n; return mk(`${t.full} — кімнің шығармасы?`, r, others(AU.map(a => a.n), r), t.id, 'Шығарма мен автор'); },
    genre() { const t = pick(WORKS.filter(w => w.genre)); const g = s => s.split(' (')[0]; const r = g(t.genre); return mk(`${t.full}: жанры қандай?`, r, others(WORKS.map(w => g(w.genre || '')).filter(Boolean), r), t.id, 'Жанр'); },
    char() { const c = pick(CR); const t = TMAP[c.w]; return mk(`«${c.n}» — қай шығарманың кейіпкері?`, t.t, others(WORKS.map(w => w.t), t.t), t.id, 'Кейіпкерлер'); },
    say() { const c = pick(CR.filter(x => x.say && !/\(/.test(x.say))); return mk(`«${c.say}» — бұл кімнің сөзі?`, c.n, others(CR.filter(x => x.say && x.w !== c.w).map(x => x.n), c.n), c.w, 'Кім айтты?'); },
    term() {
      const [t, d] = pick(TERMS.filter(x => x[0] !== 'Энциклопедия'));
      const stem = t.toLowerCase().slice(0, Math.max(4, t.length - 3));
      const masked = d.replace(new RegExp(stem.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[^\\s,.;:»]*', 'gi'), '…');
      return mk(masked, t, others(TERMS.map(x => x[0]), t), (TERMMAP[t.toLowerCase()].topics[0]) || '', 'Әдебиет теориясы');
    },
    word() { const w = pick(WORDS); return mk(`«${w[0]}» сөзінің мағынасы қандай?`, w[1], others(WORDS.filter(x => x[2] !== w[2]).map(x => x[1]), w[1]), w[2], 'Сөзмаржан'); }
  };
  function buildQuiz(mode) {
    const recipe = { mix: ['hand', 'hand', 'hand', 'author', 'char', 'say', 'term', 'word', 'genre', 'hand'], works: ['hand', 'author', 'genre', 'hand', 'author', 'hand', 'genre', 'author', 'hand', 'hand'], chars: ['char', 'say', 'char', 'say', 'char', 'char', 'say', 'char', 'say', 'char'], terms: Array(10).fill('term'), words: Array(10).fill('word') }[mode];
    const seen = new Set(), out = [];
    recipe.forEach(k => { for (let n = 0; n < 30; n++) { const x = G[k](); if (!seen.has(x.q) && x.opts.length === 4) { seen.add(x.q); out.push(x); break; } } });
    return out;
  }
  let QS = null;
  function quizStart() {
    const best = store.get('best', {});
    return `<div class="wrap qz">
      <header class="ph"><span class="eyebrow">Білімді тексер</span><h1>Сайыс</h1>
      <p class="lead">Әр сайыста 10 сұрақ. Сұрақтар әр жолы жаңадан құрастырылады.</p></header>
      <div class="modes">${MODES.map(([k, n, d, ic]) => `<button type="button" class="mode" data-mode="${k}">${ic}<b>${n}</b><span>${d}</span>${best[k] != null ? `<span class="muted">Ең жақсы нәтиже: ${best[k]}/10</span>` : ''}</button>`).join('')}</div></div>`;
  }
  function quizQuestion() {
    const s = QS, x = s.qs[s.i], keys = ['А', 'Ә', 'Б', 'В'];
    return `<div class="wrap qz">
      <div class="qhead"><span>${esc(MODES.find(m => m[0] === s.mode)[1])}</span><span>${s.i + 1} / ${s.qs.length} · Ұпай: ${s.score}</span></div>
      <div class="qbar"><i style="width:${(s.i) / s.qs.length * 100}%"></i></div>
      <div class="qq card"><div class="ctx">${esc(x.ctx || '')}</div><h2 id="qtitle">${esc(x.q)}</h2>
        <div class="opts" role="group" aria-labelledby="qtitle">${x.opts.map((o, k) => `<button type="button" class="opt" data-opt="${k}"><span class="k">${keys[k]}</span><span>${esc(o)}</span></button>`).join('')}</div>
        <div class="fb" id="qfb" aria-live="polite"></div>
      </div>
      <p class="muted ui" style="margin-top:14px;font-size:14px"><a href="#quiz" data-quit>← Сайыстан шығу</a></p></div>`;
  }
  function quizEnd() {
    const s = QS, best = store.get('best', {});
    const prevBest = best[s.mode];
    if (prevBest == null || s.score > prevBest) { best[s.mode] = s.score; store.set('best', best); }
    const msg = s.score >= 9 ? 'Керемет! Оқулықты жақсы білесің.' : s.score >= 6 ? 'Жақсы нәтиже! Қателескен тақырыптарды қайталап шық.' : 'Тағы бір рет оқып, қайта байқап көр.';
    const wrongRefs = Array.from(new Set(s.wrong.map(x => x.ref).filter(r => TMAP[r])));
    return `<div class="wrap qz"><div class="score card">
      <span class="eyebrow">${esc(MODES.find(m => m[0] === s.mode)[1])}</span>
      <div class="big">${s.score}/${s.qs.length}</div><p class="lead" style="text-align:center">${msg}</p>
      ${prevBest != null ? `<p class="muted ui">Бұрынғы ең жақсы нәтиже: ${prevBest}/10</p>` : ''}
      <div class="chips" style="justify-content:center">${wrongRefs.map(r => `<a class="chip" href="#t-${r}">${esc(TMAP[r].t)}</a>`).join('')}</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:center;margin-top:8px"><button type="button" class="btn" data-mode="${s.mode}">Қайта ойнау</button><a class="btn alt" href="#quiz" data-quit>Басқа сайыс</a></div>
    </div></div>`;
  }
  function quizMount(html) { const m = $('#app'); m.innerHTML = `<div class="page">${html}</div>`; quizBind(); }
  function quizBind() {
    $$('[data-mode]').forEach(b => b.addEventListener('click', () => {
      const mode = b.dataset.mode; QS = { mode, qs: buildQuiz(mode), i: 0, score: 0, wrong: [], done: false };
      quizMount(quizQuestion()); window.scrollTo(0, 0);
    }));
    $$('[data-quit]').forEach(a => a.addEventListener('click', e => { e.preventDefault(); QS = null; quizMount(quizStart()); }));
    $$('[data-opt]').forEach(b => b.addEventListener('click', () => answer(+b.dataset.opt)));
  }
  function answer(k) {
    const s = QS; if (!s || s.done) return;
    const x = s.qs[s.i], ok = x.opts[k] === x.a;
    s.done = true;
    if (ok) s.score++; else s.wrong.push(x);
    $$('[data-opt]').forEach((b, n) => { b.disabled = true; if (x.opts[n] === x.a) b.classList.add('right'); else if (n === k) b.classList.add('wrong'); });
    const last = s.i === s.qs.length - 1;
    const ref = TMAP[x.ref];
    $('#qfb').innerHTML = `<span class="msg ${ok ? 'ok' : 'no'}">${ok ? 'Дұрыс!' : 'Қате. Дұрыс жауабы: ' + esc(x.a)}</span>${ref ? `<a href="#t-${ref.id}" class="ui" style="font-size:14px">${esc(ref.t)} →</a>` : ''}<button type="button" class="btn" id="qnext">${last ? 'Нәтижені көру' : 'Келесі сұрақ →'}</button>`;
    const nb = $('#qnext'); nb.focus();
    nb.addEventListener('click', () => { if (last) quizMount(quizEnd()); else { s.i++; s.done = false; quizMount(quizQuestion()); $('[data-opt]').focus({ preventScroll: true }); } });
  }

  /* =====================================================================
     Терезе (modal), іздеу, «Тағы» мәзірі
     ===================================================================== */
  let lastFocus = null, onClose = null;
  function openModal(inner, cb) {
    closeModal(true);
    lastFocus = document.activeElement;
    const m = document.createElement('div');
    m.className = 'modal';
    m.innerHTML = `<div class="shade" data-close></div><div class="sheet" role="dialog" aria-modal="true" aria-labelledby="mtitle"><button type="button" class="ib x" data-close aria-label="Жабу">${UI.close}</button>${inner}</div>`;
    document.body.appendChild(m);
    document.body.style.overflow = 'hidden';
    onClose = cb || null;
    setTimeout(() => { const f = $('.sheet input', m) || $('.sheet .x', m); if (f) f.focus({ preventScroll: true }); }, 20);
  }
  function closeModal(silent) {
    const m = $('.modal'); if (!m) return;
    m.remove(); document.body.style.overflow = '';
    const cb = onClose; onClose = null;
    if (cb) cb();
    if (!silent && lastFocus && document.contains(lastFocus)) lastFocus.focus({ preventScroll: true });
  }
  function searchResults(q) {
    q = norm(q.trim());
    if (!q) return '<p class="muted ui">Шығарманы, авторды, кейіпкерді, терминді немесе сөзді жазыңыз.</p>';
    const has = s => norm(s).includes(q);
    const groups = [
      ['Шығармалар мен тақырыптар', TP.filter(t => has(t.t) || has(t.full || '') || has(workBy(t))).map(t => [`#t-${t.id}`, t.full || t.t, workBy(t)])],
      ['Ақын-жазушылар', AU.filter(a => has(a.n)).map(a => [`#a-${a.id}`, a.n, a.y])],
      ['Кейіпкерлер', CR.filter(c => has(c.n)).map(c => [`#k-${c.id}`, c.n, TMAP[c.w].t])],
      ['Әдебиет теориясы', TERMS.filter(x => has(x[0])).map(x => ['#glossary', x[0], x[1]])],
      ['Сөзмаржан', WORDS.filter(w => has(w[0])).map(w => [`#t-${w[2]}`, w[0], w[1]])]
    ].filter(g => g[1].length);
    if (!groups.length) return '<p class="empty">Ештеңе табылмады.</p>';
    return groups.map(([h, list]) => `<div><h3>${h}</h3><ul>${list.slice(0, 6).map(([href, n, s]) => `<li><a href="${href}"${href === '#glossary' ? ` data-gterm="${esc(n)}"` : ''}>${esc(n)}<small>${esc(s)}</small></a></li>`).join('')}</ul></div>`).join('');
  }
  function openSearch() {
    openModal(`<h2 id="mtitle">Іздеу</h2><label class="searchbox" style="margin:14px 0 0">${UI.search}<span class="sr">Іздеу сөзі</span><input id="sQ" type="search" placeholder="Мысалы: Көксерек, Мағжан, теңеу" autocomplete="off"></label><div class="results" id="sRes">${searchResults('')}</div>`);
    const inp = $('#sQ'), res = $('#sRes');
    inp.addEventListener('input', () => { res.innerHTML = searchResults(inp.value); });
  }
  function openMore() {
    openModal(`<span class="eyebrow">Мәзір</span><h2 id="mtitle">Тағы</h2>
      <div class="more-grid">
        <a href="#authors">${UI.quill}Ақын-жазушылар</a>
        <a href="#timeline">${UI.clock}Уақыт сызығы</a>
        <a href="#glossary">${UI.dict}Сөздік</a>
        <a href="#works">${UI.books}Мазмұны</a>
        <button type="button" data-act="search">${UI.search}Іздеу</button>
        <button type="button" data-act="theme">${isDark() ? UI.sun : UI.moon}Түсті ауыстыру</button>
      </div>
      <div class="divider" style="margin-top:22px">${ORN}</div>
      <div class="sh-sig" lang="en" translate="no"><span class="sh-sig__by">Crafted by <b>Claude Opus 5.5</b> (UltraCode)</span><span class="sh-sig__name">sheinorshin</span><a class="sh-sig__mail" href="mailto:sheinorshin&#64;gmail.com">sheinorshin&#64;gmail.com</a></div>`);
  }

  /* =====================================================================
     Бағыттау (routing)
     ===================================================================== */
  const main = $('#app');
  function setNav(key) {
    $$('[data-nav]').forEach(a => a.classList.toggle('on', a.dataset.nav === key));
    $$('[data-tab]').forEach(a => a.classList.toggle('on', a.dataset.tab === key));
  }
  function render() {
    closeModal(true);
    const h = decodeURIComponent((location.hash || '').slice(1)) || 'home';
    let html = '', nav = h, title = '', post = null, after = null;
    if (h.startsWith('t-') && TMAP[h.slice(2)]) { const t = TMAP[h.slice(2)]; html = topicPage(t); nav = 'works'; title = (t.full || t.t).replace(/[«»]/g, ''); }
    else if (h.startsWith('c-') && chOf(+h.slice(2))) { const c = chOf(+h.slice(2)); html = chapterPage(c); nav = 'works'; title = c.r + ' тарау'; }
    else if (h.startsWith('a-') && AMAP[h.slice(2)]) { const a = AMAP[h.slice(2)]; html = authorPage(a); nav = 'authors'; title = a.n; }
    else if (h.startsWith('k-') && CMAP[h.slice(2)]) {
      html = characters(); post = charactersPost; nav = 'characters'; title = CMAP[h.slice(2)].n;
      after = () => { charModal(h.slice(2)); onClose = () => { try { history.replaceState(null, '', '#characters'); } catch (e) { /* жоқ */ } }; };
    }
    else if (h === 'works') { html = works(); title = 'Шығармалар'; }
    else if (h === 'authors') { html = authors(); title = 'Ақын-жазушылар'; }
    else if (h === 'characters') { html = characters(); post = charactersPost; title = 'Кейіпкерлер'; }
    else if (h === 'timeline') { html = timeline(); post = timelinePost; title = 'Уақыт сызығы'; }
    else if (h === 'glossary') { html = glossary(); post = glossaryPost; title = 'Сөздік'; }
    else if (h === 'quiz') { QS = null; html = quizStart(); post = quizBind; title = 'Сайыс'; }
    else { html = home(); nav = 'home'; }
    main.innerHTML = `<div class="page">${html}</div>`;
    setNav(nav);
    document.title = title ? `${title} · Қазақ әдебиеті 7` : 'Қазақ әдебиеті · 7-сынып';
    window.scrollTo(0, 0);
    main.focus({ preventScroll: true });
    if (post) post();
    if (after) after();
  }
  window.addEventListener('hashchange', render);

  /* Жалпы басулар */
  document.addEventListener('click', e => {
    const ch = e.target.closest('[data-char]');
    if (ch) { e.preventDefault(); charModal(ch.dataset.char); return; }
    if (e.target.closest('[data-close]')) { closeModal(); return; }
    const rd = e.target.closest('[data-read]');
    if (rd) {
      const id = rd.dataset.read;
      if (READ.has(id)) READ.delete(id); else READ.add(id);
      saveRead();
      const on = READ.has(id);
      rd.className = 'btn ' + (on ? 'done' : 'alt'); rd.setAttribute('aria-pressed', String(on));
      rd.innerHTML = on ? UI.check + ' Оқылды' : 'Оқыдым деп белгілеу';
      return;
    }
    const jump = e.target.closest('[data-jump]');
    if (jump) { e.preventDefault(); const el = document.getElementById(jump.getAttribute('href').slice(1)); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
    const gt = e.target.closest('[data-gterm]');
    if (gt) { glTab = 'terms'; glQ = gt.dataset.gterm; if (location.hash === '#glossary') { e.preventDefault(); render(); } return; }
    const act = e.target.closest('[data-act]');
    if (act) {
      if (act.dataset.act === 'search') { openSearch(); }
      if (act.dataset.act === 'theme') { toggleTheme(); closeModal(); }
      return;
    }
    if (e.target.closest('#searchBtn')) { openSearch(); return; }
    if (e.target.closest('#themeBtn')) { toggleTheme(); return; }
    if (e.target.closest('#moreBtn')) { openMore(); return; }
    /* Терезедегі сілтеме сол бетке апарса, терезе жабылады */
    const a = e.target.closest('.modal a[href^="#"]');
    if (a && a.getAttribute('href') === location.hash) { closeModal(); }
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && $('.modal')) { closeModal(); return; }
    const typing = /input|textarea|select/i.test((e.target && e.target.tagName) || '');
    if (e.key === '/' && !typing && !$('.modal')) { e.preventDefault(); openSearch(); return; }
    if (QS && !QS.done && !typing && !$('.modal')) {
      const map = { '1': 0, '2': 1, '3': 2, '4': 3 };
      if (e.key in map) answer(map[e.key]);
    }
  });

  /* Іске қосу */
  $('#searchBtn').innerHTML = UI.search;
  $('#moreBtnIco') && ($('#moreBtnIco').innerHTML = UI.more);
  applyTheme(root.getAttribute('data-theme'));
  render();
})();
