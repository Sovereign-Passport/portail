/* ============ SPID i18n — shared, no external asset ============
 * One table per concept: [en, fr, es]. The source string (EN or FR, as it
 * appears in the code) is the key, so nothing has to be rewritten in place.
 * A MutationObserver also translates dynamically-inserted text and prefixes
 * (e.g. "Vous : <texte>" -> "You: <texte>").
 *
 * Language: localStorage 'spidLang' (shared by Portail + Passport, same
 * origin) -> navigator.languages -> EN (default).
 */
(function (global) {
  var LANGS = ['fr', 'en', 'es'];

  var ROWS = [
    // ── brand / nav ──────────────────────────────────────────────
    ['Sovereign Passport', 'Passeport Souverain', 'Pasaporte Soberano'],
    ['Universal Switchboard', 'Switchboard Universel', 'Central Universal'],
    ['Portal to sovereign services', 'Portail vers les services souverains', 'Portal a los servicios soberanos'],
    ['Assist', 'Assist', 'Asistente'],
    ['Billboard', 'Billboard', 'Tabl\u00f3n'],
    ['Calendar', 'Calendrier', 'Calendario'],
    ['Messages', 'Messages', 'Mensajes'],
    ['The math is the authority. Not the institution.', 'Les math\u00e9matiques font autorit\u00e9. Pas l\u2019institution.', 'Las matem\u00e1ticas son la autoridad. No la instituci\u00f3n.'],
    ['Open your Passport \u2192', 'Ouvrir votre Passport \u2192', 'Abrir su Pasaporte \u2192'],

    // ── assist ───────────────────────────────────────────────────
    ['Your DID', 'Votre DID', 'Su DID'],
    ['Vault password', 'Mot de passe du coffre', 'Contrase\u00f1a del almac\u00e9n'],
    ['Your passport password', 'Votre mot de passe passport', 'Su contrase\u00f1a del pasaporte'],
    ['Unlock \u2192', 'D\u00e9verrouiller \u2192', 'Desbloquear \u2192'],
    ['your doors', 'vos portes', 'sus puertas'],
    ['Checking this device\u2026', 'V\u00e9rification de cet appareil\u2026', 'Comprobando este dispositivo\u2026'],
    ['No doors open for this passport yet. Ask your vine for an invitation.', 'Aucune porte ouverte pour ce passeport. Demandez une invitation \u00e0 votre vine.', 'A\u00fan no hay puertas abiertas para este pasaporte. Pida una invitaci\u00f3n a su vine.'],
    ['No Passport found on this device', 'Aucun Passeport sur cet appareil', 'Ning\u00fan Pasaporte en este dispositivo'],
    ['conversation', 'conversation', 'conversaci\u00f3n'],
    ['\u00c9crivez votre demande (ou enregistrez un court message)\u2026', '\u00c9crivez votre demande (ou enregistrez un court message)\u2026', 'Escriba su solicitud (o grabe un mensaje corto)\u2026'],
    ['Micros', 'Micros', 'Micr\u00f3fonos'],
    ['Enregistrer', 'Enregistrer', 'Grabar'],
    ['Envoyer', 'Envoyer', 'Enviar'],

    // ── billboard ────────────────────────────────────────────────
    ['Cluster', 'Cluster', 'Cl\u00faster'],
    ['No Cluster connected to this Passport.', 'Aucun cluster reli\u00e9 \u00e0 ce passeport.', 'Ning\u00fan cl\u00faster conectado a este pasaporte.'],
    ['Refresh', 'Actualiser', 'Actualizar'],
    ['New post', 'Nouvelle annonce', 'Nueva publicaci\u00f3n'],
    ['Open your Passport to publish', 'Ouvrez votre Passport pour publier', 'Abra su Pasaporte para publicar'],
    ['Title', 'Titre', 'T\u00edtulo'],
    ['Message', 'Message', 'Mensaje'],
    ['Optional expiration', 'Expiration facultative', 'Caducidad opcional'],
    ['Cancel', 'Annuler', 'Cancelar'],
    ['Review & sign \u2192', 'V\u00e9rifier et signer \u2192', 'Revisar y firmar \u2192'],
    ['Confirm announcement', 'Confirmer l\u2019annonce', 'Confirmar el anuncio'],
    ['Expires', 'Expire', 'Caduca'],
    ['Back', 'Retour', 'Atr\u00e1s'],
    ['Sign & publish', 'Signer et publier', 'Firmar y publicar'],
    ['\u2014 Public (sans cluster) \u2014', '\u2014 Public (sans cluster) \u2014', '\u2014 P\u00fablico (sin cl\u00faster) \u2014'],
    ['No announcements yet.', 'Aucune annonce.', 'A\u00fan no hay anuncios.'],
    ['Loading\u2026', 'Chargement\u2026', 'Cargando\u2026'],
    ['Retry', 'R\u00e9essayer', 'Reintentar'],
    ['Could not load public announcements: ', 'Impossible de charger les annonces publiques : ', 'No se pudieron cargar los anuncios p\u00fablicos: '],
    ['Could not load announcements: ', 'Impossible de charger les annonces : ', 'No se pudieron cargar los anuncios: '],

    // ── calendar ─────────────────────────────────────────────────
    ['Today', 'Aujourd\u2019hui', 'Hoy'],
    ['Today', 'Aujourd\u0027hui', 'Hoy'],
    ['Previous month', 'Mois pr\u00e9c\u00e9dent', 'Mes anterior'],
    ['Next month', 'Mois suivant', 'Mes siguiente'],
    ['Personal', 'Personnel', 'Personal'],
    ['No entries this month.', 'Aucune entr\u00e9e dans ce mois.', 'Ninguna entrada este mes.'],
    ['Calendar unavailable (no scope responded).', 'Calendrier indisponible (aucune port\u00e9e n\u2019a r\u00e9pondu).', 'Calendario no disponible (ning\u00fan \u00e1mbito respondi\u00f3).'],
    ['No calendar accessible.', 'Aucun calendrier accessible.', 'Ning\u00fan calendario accesible.'],
    ['Open your passport to see your calendar.', 'Ouvrez votre passport pour voir votre calendrier.', 'Abra su pasaporte para ver su calendario.'],
    ['Service in preparation', 'Service en pr\u00e9paration', 'Servicio en preparaci\u00f3n'],

    // ── assist (runtime) ─────────────────────────────────────────
    ['Planning\u2026', 'Planification\u2026', 'Planificando\u2026'],
    ['Signed execution\u2026', 'Ex\u00e9cution sign\u00e9e\u2026', 'Ejecuci\u00f3n firmada\u2026'],
    ['Result: ', 'R\u00e9sultat : ', 'Resultado: '],
    ['Error: ', 'Erreur : ', 'Error: '],
    ['Transcription error: ', 'Erreur transcription : ', 'Error de transcripci\u00f3n: '],
    ['Assist: ', 'Assist : ', 'Asistente: '],
    ['Orbit: ', 'Orbit : ', 'Orbit: '],
    ['You (voice): ', 'Vous (voix) : ', 'Usted (voz): '],
    ['You: ', 'Vous : ', 'Usted: '],
    ['Proposed plan (', 'Plan propos\u00e9 (', 'Plan propuesto ('],
    ['Confirm and run', 'Confirmer et ex\u00e9cuter', 'Confirmar y ejecutar'],
    ['Transcribing\u2026', 'Transcription\u2026', 'Transcribiendo\u2026'],
    ['Transcription unavailable: ', 'Transcription indisponible : ', 'Transcripci\u00f3n no disponible: '],
    ['Transcription ready \u2014 review then \u00ab Send \u00bb.', 'Transcription pr\u00eate \u2014 v\u00e9rifie puis \u00ab Envoyer \u00bb.', 'Transcripci\u00f3n lista \u2014 revise y pulse \u00abEnviar\u00bb.'],
    ['Recording not supported by this browser.', 'Enregistrement non support\u00e9 par ce navigateur.', 'Grabaci\u00f3n no compatible con este navegador.'],
    ['Nothing recorded.', 'Rien enregistr\u00e9.', 'Nada grabado.'],
    ['Silent mic: no sound captured. Choose another input in \u00ab Micros \u00bb and check it is not muted.', 'Micro silencieux : aucun son capt\u00e9. Choisis une autre entr\u00e9e dans la liste \u00ab Micros \u00bb et v\u00e9rifie qu\u2019elle n\u2019est pas muette.', 'Micr\u00f3fono silencioso: no se capt\u00f3 sonido. Elija otra entrada en \u00abMicr\u00f3fonos\u00bb y compruebe que no est\u00e9 silenciada.'],
    ['Microphone unavailable: ', 'Micro indisponible : ', 'Micr\u00f3fono no disponible: '],
    ['Microphone selected.', 'Micro s\u00e9lectionn\u00e9.', 'Micr\u00f3fono seleccionado.'],
    ['Recording\u2026 (click Stop)', 'Enregistrement\u2026 (cliquez Stop)', 'Grabando\u2026 (pulse Stop)']
  ];

  // Build per-language dictionaries from the rows.
  var DICT = { en: {}, fr: {}, es: {} };
  ROWS.forEach(function (r) {
    var en = r[0], fr = r[1], es = r[2];
    DICT.en[en] = en; DICT.en[fr] = en;
    DICT.fr[en] = fr; DICT.fr[fr] = fr;
    DICT.es[en] = es; DICT.es[fr] = es;
  });
  // Keys sorted longest-first (prefix matching).
  var KEYS = Object.keys(DICT.es).sort(function (a, b) { return b.length - a.length; });

  function detect() {
    try { var s = localStorage.getItem('spidLang'); if (s && LANGS.indexOf(s) >= 0) return s; } catch (e) {}
    var ls = navigator.languages || [navigator.language || 'en'];
    for (var i = 0; i < ls.length; i++) {
      var l = String(ls[i] || '').slice(0, 2).toLowerCase();
      if (LANGS.indexOf(l) >= 0) return l;
    }
    return 'en';
  }

  var lang = detect();

  function xlate(raw) {
    var d = DICT[lang];
    if (!d || lang === 'source') return raw;
    var lead = (raw.match(/^\s*/) || [''])[0];
    var rest = raw.slice(lead.length);
    if (d[rest] !== undefined) return lead + d[rest];
    for (var i = 0; i < KEYS.length; i++) {
      var k = KEYS[i];
      if (rest.indexOf(k) === 0 && d[k] !== undefined) return lead + d[k] + rest.slice(k.length);
    }
    return raw;
  }

  var ORIG = new WeakMap();

  function txt(node) {
    var src;
    if (ORIG.has(node)) { src = ORIG.get(node); }
    else { src = node.nodeValue; ORIG.set(node, src); }
    if (!src || !src.trim()) return;
    var out = xlate(src);
    if (node.nodeValue !== out) node.nodeValue = out;
  }

  function attrs(el) {
    ['placeholder', 'title', 'aria-label'].forEach(function (a) {
      if (!el.getAttribute) return;
      var key = 'data-spid-src-' + a;
      var src = el.getAttribute(key);
      if (src === null) {
        src = el.getAttribute(a);
        if (!src) return;
        el.setAttribute(key, src);
      }
      var out = xlate(src);
      if (el.getAttribute(a) !== out) el.setAttribute(a, out);
    });
  }

  function walk(node) {
    if (node.nodeType === 3) { txt(node); return; }
    if (node.nodeType !== 1) return;
    var tag = node.tagName;
    if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'TEXTAREA' || tag === 'CODE' || tag === 'PRE') return;
    attrs(node);
    for (var i = 0; i < node.childNodes.length; i++) walk(node.childNodes[i]);
  }

  function apply(root) { walk(root || document.body); }

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
    // Durable mirror inside the DID's vault (best effort, may be locked).
    if (typeof global.spidPersistLang === 'function') {
      try { global.spidPersistLang(l); } catch (e) {}
    }
  }

  // Re-render in the vault's stored language, once the vault is known.
  function adopt(l) {
    if (LANGS.indexOf(l) < 0 || l === lang) return;
    lang = l;
    try { localStorage.setItem('spidLang', l); } catch (e) {}
    document.documentElement.lang = l;
    document.documentElement.setAttribute('data-spid-lang', l);
    apply(document.body);
    wire();
  }

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
