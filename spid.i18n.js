/* ============ SPID i18n — keyed catalog, no external asset ============
 *
 * Catalogs: i18n/catalogs.js — keys are language-neutral.
 * Legacy source lookup is kept so existing literals already in the DOM
 * continue to translate while new UI code uses keys/data-i18n.
 *
 * Language: localStorage 'spidLang' (shared by Portail + Passport, same
 * origin) -> navigator.languages -> EN (default).
 */
(function (global) {
  var LANGS = ['fr', 'en', 'es'];
  var C = global.SPID_I18N_CATALOG || { en: {}, fr: {}, es: {} };

  function detect() {
    try {
      var s = localStorage.getItem('spidLang');
      if (s && LANGS.indexOf(s) >= 0) return s;
    } catch (e) {}
    var ls = navigator.languages || [navigator.language || 'en'];
    for (var i = 0; i < ls.length; i++) {
      var l = String(ls[i] || '').slice(0, 2).toLowerCase();
      if (LANGS.indexOf(l) >= 0) return l;
    }
    return 'en';
  }

  var lang = detect();

  // Build source -> key index from every catalog value (legacy compatibility).
  var SOURCE = {};
  var PREFIX = [];
  LANGS.forEach(function (l) {
    Object.keys(C[l] || {}).forEach(function (key) {
      var value = C[l][key];
      if (typeof value === 'string' && value && SOURCE[value] === undefined) {
        SOURCE[value] = key;
        PREFIX.push(value);
      }
    });
  });
  PREFIX.sort(function (a, b) { return b.length - a.length; });

  function t(key, vars) {
    var table = C[lang] || {};
    var out = table[key];
    if (out === undefined) out = (C.en && C.en[key]);
    if (out === undefined) out = key;
    if (vars && typeof out === 'string') {
      out = out.replace(/\{(\w+)\}/g, function (_, name) {
        return vars[name] !== undefined ? String(vars[name]) : '{' + name + '}';
      });
    }
    return out;
  }

  function xlate(raw) {
    if (!raw || !raw.trim()) return raw;
    var lead = (raw.match(/^\s*/) || [''])[0];
    var rest = raw.slice(lead.length);
    var exact = SOURCE[rest];
    if (exact !== undefined) return lead + t(exact);
    for (var i = 0; i < PREFIX.length; i++) {
      var k = PREFIX[i];
      if (rest.indexOf(k) === 0) return lead + t(SOURCE[k]) + rest.slice(k.length);
    }
    return raw;
  }

  var ORIG = new WeakMap();

  function txt(node) {
    var src;
    if (ORIG.has(node)) src = ORIG.get(node);
    else { src = node.nodeValue; ORIG.set(node, src); }
    if (!src || !src.trim()) return;
    var out = xlate(src);
    if (node.nodeValue !== out) node.nodeValue = out;
  }

  function translateAttrs(el) {
    ['placeholder', 'title', 'aria-label'].forEach(function (a) {
      if (!el.getAttribute) return;
      var key = el.getAttribute('data-i18n-' + a);
      if (key) {
        var out = t(key);
        if (el.getAttribute(a) !== out) el.setAttribute(a, out);
        return;
      }
      var srcKey = 'data-spid-src-' + a;
      var src = el.getAttribute(srcKey);
      if (src === null) {
        src = el.getAttribute(a);
        if (!src) return;
        el.setAttribute(srcKey, src);
      }
      var translated = xlate(src);
      if (el.getAttribute(a) !== translated) el.setAttribute(a, translated);
    });
  }

  function walk(node) {
    if (node.nodeType === 3) {
      if (node.parentElement && node.parentElement.hasAttribute('data-i18n')) return;
      txt(node);
      return;
    }
    if (node.nodeType !== 1) return;
    var tag = node.tagName;
    if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'TEXTAREA' || tag === 'CODE' || tag === 'PRE') {
      translateAttrs(node);
      return;
    }
    var key = node.getAttribute('data-i18n');
    if (key) {
      node.textContent = t(key);
      translateAttrs(node);
      return;
    }
    translateAttrs(node);
    var children = node.childNodes;
    for (var i = 0; i < children.length; i++) walk(children[i]);
  }

  function apply(root) {
    walk(root || document.body);
  }

  function wire() {
    var btns = document.querySelectorAll('.lang-btn[data-lang]');
    for (var i = 0; i < btns.length; i++) {
      (function (b) {
        b.setAttribute('aria-pressed', b.getAttribute('data-lang') === lang ? 'true' : 'false');
        b.addEventListener('click', function () { setLang(b.getAttribute('data-lang')); });
      })(btns[i]);
    }
  }

  function start() {
    document.documentElement.lang = lang;
    document.documentElement.setAttribute('data-spid-lang', lang);
    apply(document.body);
    wire();
    try {
      new MutationObserver(function (muts) {
        for (var i = 0; i < muts.length; i++) {
          var m = muts[i];
          if (m.type === 'childList') {
            for (var j = 0; j < m.addedNodes.length; j++) apply(m.addedNodes[j]);
          } else if (m.type === 'characterData') {
            txt(m.target);
          }
        }
      }).observe(document.body, { childList: true, subtree: true, characterData: true });
    } catch (e) {}
  }

  function setLang(l) {
    if (LANGS.indexOf(l) < 0) l = 'en';
    lang = l;
    try { localStorage.setItem('spidLang', l); } catch (e) {}
    document.documentElement.lang = l;
    document.documentElement.setAttribute('data-spid-lang', l);
    apply(document.body);
    wire();
    if (typeof global.spidPersistLang === 'function') {
      try { global.spidPersistLang(l); } catch (e) {}
    }
  }

  function adopt(l) {
    if (LANGS.indexOf(l) < 0 || l === lang) return;
    lang = l;
    try { localStorage.setItem('spidLang', l); } catch (e) {}
    document.documentElement.lang = l;
    document.documentElement.setAttribute('data-spid-lang', l);
    apply(document.body);
    wire();
  }

  global.spidT = t;
  global.t = t;
  global.spidXlate = xlate;
  global.spidLang = function () { return lang; };
  global.spidSetLang = setLang;
  global.spidAdoptLang = adopt;
  global.spidApply = apply;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})(window);
