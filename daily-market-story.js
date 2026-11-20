/*
 * SPID Portail — Daily Market Story (initial testing build)
 *
 * Read-only client for the public `market/story` Switchboard route, which is
 * a sanitized projection of the Nugget service. No Passport key is required
 * and no account, position or credential data is requested.
 *
 * The statistical engine lives in Nugget. This module only presents the
 * readings and the deterministic expression selected by the service. It
 * never fabricates a value: missing axes stay visibly missing.
 *
 * ES2017 target. Forbidden: ?. ?? 0n 600_000 catch{} {...obj}
 */
(function (global) {
  'use strict';

  var SWITCH_HOST = global.SPID_SWITCH_HOST || 'https://sb.sovereign-passport.id';

  var AXIS_KEYS = [
    'energy', 'inflation', 'consumers', 'confidence', 'employment', 'growth',
    'financing', 'business', 'credit', 'volatility', 'participation', 'outlook'
  ];

  var _overlay = null;
  var _body = null;
  var _titleEl = null;
  var _metaEl = null;
  var _refreshBtn = null;
  var _payload = null;
  var _loading = false;
  var _priming = false;
  var _refreshNote = '';
  var _fixture = false;
  var _lastFocus = null;

  function t(key, vars) {
    if (typeof global.spidT === 'function') return global.spidT(key, vars);
    return key;
  }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function parseDate(value) {
    if (!value) return null;
    var d = new Date(value);
    return isNaN(d.getTime()) ? null : d;
  }

  function fmtDate(d) {
    if (!d) return '—';
    try {
      return new Intl.DateTimeFormat(
        (global.spidLang && global.spidLang()) || 'en',
        { dateStyle: 'medium', timeStyle: 'short' }
      ).format(d);
    } catch (e) {
      return d.toISOString();
    }
  }

  function statusLabel(status) {
    if (status === 'live') return t('dms.status.live');
    if (status === 'stale') return t('dms.status.stale');
    if (status === 'offline') return t('dms.status.offline');
    return t('dms.status.unavailable');
  }

  function statusClass(status) {
    if (status === 'live') return 'dms-status is-live';
    if (status === 'stale') return 'dms-status is-stale';
    return 'dms-status is-offline';
  }

  function axisLabel(key) {
    return t('dms.axis.' + key);
  }

  function directionLabel(direction) {
    if (direction === 'up') return t('dms.direction.up');
    if (direction === 'down') return t('dms.direction.down');
    if (direction === 'flat') return t('dms.direction.flat');
    return t('dms.direction.unknown');
  }

  function axisStatusLabel(axis) {
    var base;
    if (axis.status === 'live') base = t('dms.axis_status.live');
    else if (axis.status === 'partial') base = t('dms.axis_status.partial');
    else base = t('dms.axis_status.missing');
    if (axis.observation) {
      base += ' · ' + t('dms.observation.' + axis.observation);
    }
    return base;
  }

  function fmtNumber(value, digits) {
    if (value === null || value === undefined || isNaN(Number(value))) return '—';
    try {
      return Number(value).toLocaleString(
        (global.spidLang && global.spidLang()) || 'en',
        { maximumFractionDigits: digits === undefined ? 2 : digits }
      );
    } catch (e) {
      return String(value);
    }
  }

  function fmtSigned(value) {
    var v = Number(value);
    if (isNaN(v)) return '—';
    return (v > 0 ? '+' : '') + fmtNumber(v, 2);
  }

  // ── Data ────────────────────────────────────────────────────────────────

  function callMarket(action, data) {
    // The Switchboard is always called with POST; `method` tells it which
    // method to use on the market service (story=GET, refresh=POST).
    return fetch(SWITCH_HOST + '/api/switch', {
      method: 'POST',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        service: 'market',
        action: action,
        method: action === 'story' ? 'GET' : 'POST',
        data: data || {}
      })
    }).then(function (resp) {
      return resp.text().then(function (text) {
        var data = null;
        try { data = JSON.parse(text); } catch (e) { data = null; }
        if (!resp.ok || !data || data.kind !== 'spid/daily-market-story@1') {
          var err = new Error(
            (data && (data.error || data.message)) || ('HTTP ' + resp.status)
          );
          err.code = data && data.error;
          throw err;
        }
        return data;
      });
    });
  }

  function fetchStory() {
    return callMarket('story');
  }

  function requestRefresh(force) {
    return callMarket('refresh', { force: !!force });
  }

  // Clearly-labelled layout fixture. It is never presented as market data.
  function fixturePayload() {
    var now = new Date().toISOString();
    var direct = { energy: 1, financing: 1, credit: 1, volatility: 1, participation: 1 };
    var axes = AXIS_KEYS.map(function (key) {
      return {
        key: key,
        status: 'live',
        observation: direct[key] ? 'direct' : 'proxy',
        score: 18,
        direction: 'up',
        change_pct: 0.9,
        freshness_s: 4,
        source: 'fixture'
      };
    });
    axes[1].score = -22; axes[1].direction = 'down';
    axes[4].score = 8;  axes[4].direction = 'flat';
    axes[8].score = -35; axes[8].direction = 'down';
    axes[9].score = -41; axes[9].direction = 'down';
    axes[10].score = -30; axes[10].direction = 'down';
    axes[11].score = 12; axes[11].direction = 'up';
    return {
      kind: 'spid/daily-market-story@1',
      service: 'nugget',
      feed: 'ibkr-headless',
      generated_at: now,
      status: 'live',
      session: 'regular',
      fixture: true,
      connected: true,
      coverage: { measured: 12, total: 12 },
      expression: {
        code: 'D', word: 'Diverging', polarity: 'neutral',
        score: -4.2, coverage: 12, vocabulary: 'spid-az-v0-provisional'
      },
      axes: axes,
      regions: {
        us: { change_pct: -0.2, direction: 'down', symbols: ['SPY', 'RSP', 'IWM'] },
        china: { change_pct: 0.6, direction: 'up', symbols: ['FXI'] },
        europe: { change_pct: -0.4, direction: 'down', symbols: ['VGK'] },
        emerging: { change_pct: 0.3, direction: 'up', symbols: ['EEM', 'ILF'] },
        global: { change_pct: -0.1, direction: 'down', symbols: ['EFA'] },
        canada: { change_pct: 0.2, direction: 'up', symbols: ['EWC'] }
      },
      contradiction: { code: 'energy_up_breadth_narrow', axes: ['energy', 'participation'] },
      watch: ['volatility', 'credit', 'participation'],
      readings: [
        { pair: 'WTI / USO', feed_a: 'WTI', feed_b: 'USO', price_a: null, price_b: null,
          age_a: 4, age_b: 4, fresh: true, change_pct: 0.9, direction: 'up',
          ratio: null, z_score: null, samples: 0, volume_pressure: 0.62,
          volume_ticks: 24, macro_trend: 'bullish' },
        { pair: 'XAU / GLD', feed_a: 'XAU', feed_b: 'GLD', price_a: null, price_b: null,
          age_a: 4, age_b: 4, fresh: true, change_pct: -0.3, direction: 'down',
          ratio: null, z_score: null, samples: 0, volume_pressure: 0.47,
          volume_ticks: 18, macro_trend: 'bearish' }
      ],
      disclaimer: t('dms.fixture.disclaimer')
    };
  }

  function activePayload() {
    return _fixture ? fixturePayload() : _payload;
  }

  // ── Rendering ───────────────────────────────────────────────────────────

  function renderHeader(payload) {
    clear(_metaEl);
    if (!payload) return;

    var status = payload.fixture ? 'fixture' : payload.status;
    var badge = el('span', 'dms-status ' + (payload.fixture ? 'is-fixture' : statusClass(status).replace('dms-status ', '')));
    badge.textContent = payload.fixture ? t('dms.status.fixture') : statusLabel(payload.status);
    _metaEl.appendChild(badge);

    var date = parseDate(payload.generated_at);
    _metaEl.appendChild(el('span', 'dms-meta-date', fmtDate(date)));

    var coverage = payload.coverage || {};
    _metaEl.appendChild(el(
      'span', 'dms-meta-coverage',
      t('dms.coverage', { measured: coverage.measured || 0, total: coverage.total || AXIS_KEYS.length })
    ));

    if (payload.feed === 'ibkr-headless') {
      _metaEl.appendChild(el('span', 'dms-meta-feed', t('dms.feed.ibkr')));
    }
    if (payload.session) {
      _metaEl.appendChild(el('span', 'dms-meta-session',
        t('dms.session.' + payload.session)));
    }
    if (payload.gather && payload.gather.requested) {
      var gather = payload.gather;
      var types = gather.data_types || {};
      _metaEl.appendChild(el('span', 'dms-meta-gather', t('dms.gather', {
        received: gather.received || 0,
        requested: gather.requested || 0,
        ms: fmtNumber(gather.duration_ms, 0),
        live: types['1'] || 0,
        delayed: types['3'] || 0
      })));
    }
    if (_refreshNote) {
      _metaEl.appendChild(el('span', 'dms-refresh-note', _refreshNote));
    }
  }

  function renderExpression(payload) {
    var section = el('section', 'dms-hero');
    var expression = payload.expression || {};
    var hasExpression = expression.code && expression.word;

    var letter = el('div', 'dms-letter', hasExpression ? expression.code : '·');
    var words = el('div', 'dms-hero-words');
    var word = el('div', 'dms-word', hasExpression ? expression.word : t('dms.no_expression'));
    var line = el('div', 'dms-hero-line');
    if (hasExpression) {
      line.appendChild(el('span', 'dms-polarity is-' + expression.polarity,
        t('dms.polarity.' + expression.polarity)));
      line.appendChild(el('span', 'dms-score', t('dms.score', { score: fmtSigned(expression.score) })));
    } else {
      line.appendChild(el('span', 'dms-note', t('dms.no_expression_note')));
    }
    words.appendChild(word);
    words.appendChild(line);

    section.appendChild(letter);
    section.appendChild(words);

    if (payload.fixture) {
      section.appendChild(el('div', 'dms-fixture-banner', t('dms.fixture.banner')));
    }

    var headline = el('p', 'dms-headline', buildHeadline(payload));
    section.appendChild(headline);

    var summary = el('p', 'dms-summary', buildSummary(payload));
    section.appendChild(summary);

    return section;
  }

  function buildHeadline(payload) {
    var expression = payload.expression || {};
    if (!expression.word) return t('dms.headline.insufficient');
    var measured = (payload.axes || []).filter(function (a) {
      return a.score !== null && a.score !== undefined;
    });
    var lead = measured.slice().sort(function (a, b) {
      return Math.abs(b.score) - Math.abs(a.score);
    })[0];
    if (!lead) return t('dms.headline.pattern_simple', { word: expression.word });
    return t('dms.headline.pattern', {
      word: expression.word,
      axis: axisLabel(lead.key),
      direction: directionLabel(lead.direction)
    });
  }

  function buildSummary(payload) {
    var coverage = payload.coverage || {};
    var measured = coverage.measured || 0;
    var total = coverage.total || AXIS_KEYS.length;
    if (payload.fixture) return t('dms.summary.fixture');
    if (payload.status === 'offline') return t('dms.summary.offline');
    if (!measured) return t('dms.summary.none');
    return t('dms.summary.pattern', { measured: measured, total: total });
  }

  function renderAxes(payload) {
    var section = el('section', 'dms-section');
    section.appendChild(el('h3', 'dms-section-title', t('dms.section.axes')));
    var grid = el('div', 'dms-axis-grid');
    var byKey = {};
    (payload.axes || []).forEach(function (axis) { byKey[axis.key] = axis; });

    AXIS_KEYS.forEach(function (key) {
      var axis = byKey[key] || { key: key, status: 'missing', score: null, direction: null };
      var card = el('div', 'dms-axis is-' + axis.status);
      var head = el('div', 'dms-axis-head');
      head.appendChild(el('span', 'dms-axis-name', axisLabel(key)));
      head.appendChild(el('span', 'dms-axis-status', axisStatusLabel(axis)));
      card.appendChild(head);

      var value = el('div', 'dms-axis-value');
      if (axis.score !== null && axis.score !== undefined) {
        value.appendChild(el('span', 'dms-axis-score', fmtSigned(axis.score)));
        value.appendChild(el('span', 'dms-axis-dir', directionLabel(axis.direction)));
      } else {
        value.appendChild(el('span', 'dms-axis-missing', t('dms.axis_status.no_source')));
      }
      card.appendChild(value);

      if (axis.change_pct !== null && axis.change_pct !== undefined) {
        card.appendChild(el('div', 'dms-axis-meta',
          t('dms.axis_change', { value: fmtSigned(axis.change_pct) })));
      }
      if (axis.source) {
        card.appendChild(el('div', 'dms-axis-source', axis.source));
      }
      grid.appendChild(card);
    });

    section.appendChild(grid);
    return section;
  }

  function renderRegions(payload) {
    var regions = payload.regions || {};
    var keys = ['us', 'china', 'europe', 'emerging', 'global', 'canada'];
    var present = keys.filter(function (key) {
      return regions[key] && regions[key].change_pct !== undefined;
    });
    if (!present.length) return null;

    var section = el('section', 'dms-section');
    section.appendChild(el('h3', 'dms-section-title', t('dms.section.regions')));
    var grid = el('div', 'dms-region-grid');
    present.forEach(function (key) {
      var region = regions[key];
      var chip = el('div', 'dms-region is-' + (region.direction || 'flat'));
      chip.appendChild(el('span', 'dms-region-name', t('dms.region.' + key)));
      chip.appendChild(el('span', 'dms-region-change', fmtSigned(region.change_pct) + '%'));
      grid.appendChild(chip);
    });
    section.appendChild(grid);
    return section;
  }

  function renderContradiction(payload) {    var section = el('section', 'dms-section');
    section.appendChild(el('h3', 'dms-section-title', t('dms.section.contradiction')));
    var code = (payload.contradiction && payload.contradiction.code) || 'insufficient';
    var text = t('dms.contradiction.' + code);
    if (text === 'dms.contradiction.' + code) text = t('dms.contradiction.insufficient');
    var box = el('p', 'dms-contradiction' + (code === 'none' || code === 'insufficient' ? ' is-empty' : ''), text);
    section.appendChild(box);
    return section;
  }

  function renderWatch(payload) {
    var section = el('section', 'dms-section');
    section.appendChild(el('h3', 'dms-section-title', t('dms.section.watch')));
    var list = el('ul', 'dms-watch-list');
    var watch = payload.watch || [];
    if (!watch.length) {
      list.appendChild(el('li', 'dms-note', t('dms.watch.none')));
    } else {
      watch.forEach(function (key) {
        var axis = (payload.axes || []).filter(function (a) { return a.key === key; })[0];
        var item = el('li', 'dms-watch-item');
        item.appendChild(el('strong', null, axisLabel(key)));
        if (axis && axis.score !== null && axis.score !== undefined) {
          item.appendChild(el('span', 'dms-watch-score',
            ' ' + fmtSigned(axis.score) + ' · ' + directionLabel(axis.direction)));
        }
        list.appendChild(item);
      });
    }
    section.appendChild(list);
    return section;
  }

  function renderReadings(payload) {
    var readings = payload.readings || [];
    var symbolFeed = payload.feed === 'ibkr-headless';
    var section = el('section', 'dms-section');
    var details = document.createElement('details');
    details.className = 'dms-readings';
    var summary = document.createElement('summary');
    summary.textContent = t('dms.section.readings', { count: readings.length });
    details.appendChild(summary);

    if (!readings.length) {
      details.appendChild(el('p', 'dms-note', t('dms.readings.none')));
    } else {
      var columns = symbolFeed
        ? ['symbol', 'change', 'prev_close', 'volume', 'direction', 'freshness']
        : ['pair', 'change', 'ratio_z', 'pressure', 'macro', 'freshness'];
      var table = el('table', 'dms-readings-table');
      var thead = document.createElement('thead');
      var hr = document.createElement('tr');
      columns.forEach(function (k) {
        hr.appendChild(el('th', null, t('dms.readings.col.' + k)));
      });
      thead.appendChild(hr);
      table.appendChild(thead);
      var tbody = document.createElement('tbody');
      readings.forEach(function (r) {
        var tr = document.createElement('tr');
        var change = Number(r.change_pct);
        var direction = isNaN(change) ? '—'
          : change > 0.05 ? t('dms.direction.up')
          : change < -0.05 ? t('dms.direction.down')
          : t('dms.direction.flat');
        var age = (r.age_b !== null && r.age_b !== undefined) ? r.age_b : r.age_s;
        var ageCell = (r.fresh ? t('dms.fresh') : t('dms.stale')) +
          (age !== null && age !== undefined ? ' · ' + fmtNumber(age, 0) + 's' : '');
        if (symbolFeed) {
          tr.appendChild(el('td', null, r.symbol || r.pair || '—'));
          tr.appendChild(el('td', null, fmtSigned(r.change_pct) + '%'));
          tr.appendChild(el('td', null, fmtNumber(r.prev_close, 2)));
          tr.appendChild(el('td', null, fmtNumber(r.volume, 0)));
          tr.appendChild(el('td', null, direction));
          tr.appendChild(el('td', null, ageCell));
        } else {
          tr.appendChild(el('td', null, r.pair || r.symbol || '—'));
          tr.appendChild(el('td', null, fmtSigned(r.change_pct) + '%'));
          tr.appendChild(el('td', null,
            (r.z_score === null || r.z_score === undefined) ? '—' : fmtSigned(r.z_score)));
          tr.appendChild(el('td', null,
            (r.volume_pressure === null || r.volume_pressure === undefined)
              ? '—' : fmtNumber(r.volume_pressure, 3)));
          tr.appendChild(el('td', null, r.macro_trend || direction));
          tr.appendChild(el('td', null, ageCell));
        }
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      details.appendChild(table);
    }
    section.appendChild(details);
    return section;
  }

  function renderSources(payload) {
    var section = el('section', 'dms-section dms-sources');
    section.appendChild(el('h3', 'dms-section-title', t('dms.section.sources')));
    var list = el('ul', 'dms-source-list');
    if (payload.feed === 'ibkr-headless') {
      list.appendChild(el('li', null, t('dms.source.ibkr')));
    } else {
      list.appendChild(el('li', null, t('dms.source.nugget')));
    }
    list.appendChild(el('li', null, t('dms.source.switchboard')));
    var vocab = payload.vocabulary;
    if (vocab && vocab.counts) {
      list.appendChild(el('li', null, t('dms.vocabulary', {
        id: vocab.id,
        positive: vocab.counts.positive,
        negative: vocab.counts.negative,
        neutral: vocab.counts.neutral
      })));
    }
    if (payload.disclaimer) list.appendChild(el('li', 'dms-note', t('dms.disclaimer')));
    section.appendChild(list);
    return section;
  }

  function render(payload) {
    if (!_body) return;
    if (_titleEl) _titleEl.textContent = t('dms.title');
    var closeBtn = _overlay ? _overlay.querySelector('.dms-close') : null;
    if (closeBtn) closeBtn.setAttribute('aria-label', t('dms.close'));
    if (_refreshBtn) {
      _refreshBtn.setAttribute('aria-label', t('dms.refresh'));
      _refreshBtn.title = t('dms.refresh');
    }
    clear(_body);
    renderHeader(payload);

    if (!payload) {
      var empty = el('div', 'dms-empty');
      var emptyText = _loading ? t('dms.loading')
        : _priming ? t('dms.collecting')
        : t('dms.error.unavailable');
      empty.appendChild(el('p', null, emptyText));
      if (!_loading && !_priming) {
        var retry = el('button', 'btn btn-gold', t('dms.retry'));
        retry.type = 'button';
        retry.addEventListener('click', function () { refreshNow(true); });
        empty.appendChild(retry);
        var preview = el('button', 'btn btn-ghost', t('dms.fixture.on'));
        preview.type = 'button';
        preview.style.marginTop = '8px';
        preview.addEventListener('click', function () {
          _fixture = true;
          render(fixturePayload());
        });
        empty.appendChild(preview);
      }
      _body.appendChild(empty);
      return;
    }

    _body.appendChild(renderExpression(payload));
    _body.appendChild(renderAxes(payload));
    var regionsSection = renderRegions(payload);
    if (regionsSection) _body.appendChild(regionsSection);
    _body.appendChild(renderContradiction(payload));
    _body.appendChild(renderWatch(payload));
    _body.appendChild(renderReadings(payload));
    _body.appendChild(renderSources(payload));

    var footer = el('div', 'dms-footer');
    var toggle = el('button', 'btn btn-ghost dms-fixture-toggle', _fixture ? t('dms.fixture.off') : t('dms.fixture.on'));
    toggle.type = 'button';
    toggle.addEventListener('click', function () {
      _fixture = !_fixture;
      renderHeader(activePayload());
      render(activePayload());
    });
    footer.appendChild(toggle);
    _body.appendChild(footer);
  }

  function setRefreshBusy(busy) {
    if (!_refreshBtn) return;
    _refreshBtn.disabled = !!busy;
    _refreshBtn.classList.toggle('is-spinning', !!busy);
  }

  /**
   * Automatic one-shot gather. Used when the Billboard tab or the modal opens.
   * The server enforces the automatic cooldown, so repeated calls are cheap.
   */
  function prime() {
    if (_priming) return;
    _priming = true;
    if (!_payload && _overlay && !_overlay.hidden) render(null);
    requestRefresh(false).then(function (payload) {
      _payload = payload;
      if (_overlay && !_overlay.hidden) render(activePayload());
    }).catch(function (err) {
      if (global.console && console.warn) {
        console.warn('Daily Market Story prime failed:', err && err.message ? err.message : err);
      }
    }).then(function () {
      _priming = false;
      if (!_payload && _overlay && !_overlay.hidden) render(null);
    });
  }

  /** Manual refresh from the circular arrow in the modal header. */
  function refreshNow(force) {
    if (_loading) return;
    _fixture = false;
    _loading = true;
    _refreshNote = '';
    setRefreshBusy(true);
    render(_payload);
    requestRefresh(!!force).then(function (payload) {
      _payload = payload;
      _loading = false;
      setRefreshBusy(false);
      render(activePayload());
    }).catch(function (err) {
      _loading = false;
      setRefreshBusy(false);
      _refreshNote = t('dms.refresh.failed');
      if (global.console && console.warn) {
        console.warn('Daily Market Story refresh failed:', err && err.message ? err.message : err);
      }
      render(activePayload() || null);
      setTimeout(function () {
        if (_refreshNote === t('dms.refresh.failed')) {
          _refreshNote = '';
          if (_overlay && !_overlay.hidden) render(activePayload());
        }
      }, 5000);
    });
  }

  // ── Modal ───────────────────────────────────────────────────────────────

  function buildModal() {
    if (_overlay) return;
    _overlay = el('div', 'dms-overlay');
    _overlay.id = 'marketStoryModal';
    _overlay.setAttribute('role', 'dialog');
    _overlay.setAttribute('aria-modal', 'true');
    _overlay.setAttribute('aria-labelledby', 'dmsTitle');
    _overlay.hidden = true;

    var card = el('div', 'dms-card');
    var header = el('div', 'dms-header');
    var heading = el('div', 'dms-heading');
    _titleEl = el('h2', 'dms-title', t('dms.title'));
    _titleEl.id = 'dmsTitle';
    heading.appendChild(_titleEl);
    _metaEl = el('div', 'dms-meta');
    heading.appendChild(_metaEl);
    header.appendChild(heading);

    var close = el('button', 'dms-close', '×');
    close.type = 'button';
    close.setAttribute('aria-label', t('dms.close'));
    close.addEventListener('click', closeModal);

    var actions = el('div', 'dms-header-actions');
    _refreshBtn = el('button', 'dms-refresh');
    _refreshBtn.type = 'button';
    _refreshBtn.setAttribute('aria-label', t('dms.refresh'));
    _refreshBtn.title = t('dms.refresh');
    _refreshBtn.innerHTML =
      '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">' +
      '<path d="M20 12a8 8 0 1 1-2.34-5.66" fill="none" stroke="currentColor" ' +
      'stroke-width="2" stroke-linecap="round"/>' +
      '<path d="M20 4v5h-5" fill="none" stroke="currentColor" stroke-width="2" ' +
      'stroke-linecap="round" stroke-linejoin="round"/>' +
      '</svg>';
    _refreshBtn.addEventListener('click', function () { refreshNow(true); });
    actions.appendChild(_refreshBtn);
    actions.appendChild(close);
    header.appendChild(actions);

    card.appendChild(header);
    _body = el('div', 'dms-body');
    card.appendChild(_body);
    _overlay.appendChild(card);

    _overlay.addEventListener('click', function (e) {
      if (e.target === _overlay) closeModal();
    });
    document.body.appendChild(_overlay);
  }

  function openModal() {
    buildModal();
    _lastFocus = document.activeElement;
    _overlay.hidden = false;
    document.documentElement.classList.add('dms-open');
    var card = _overlay.querySelector('.dms-card');
    if (card) card.scrollTop = 0;
    if (_payload && !_fixture) render(_payload);
    refreshNow(false);
    var close = _overlay.querySelector('.dms-close');
    if (close) close.focus();
  }

  function closeModal() {
    if (!_overlay) return;
    _overlay.hidden = true;
    document.documentElement.classList.remove('dms-open');
    if (_lastFocus && typeof _lastFocus.focus === 'function') _lastFocus.focus();
  }

  function onKeydown(e) {
    if (!_overlay || _overlay.hidden) return;
    if (e.key === 'Escape') { closeModal(); return; }
    if (e.key !== 'Tab') return;
    var focusables = _overlay.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (!focusables.length) return;
    var first = focusables[0];
    var last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  function wire() {
    var triggers = document.querySelectorAll('[data-dms-open]');
    for (var i = 0; i < triggers.length; i++) {
      triggers[i].addEventListener('click', function (e) {
        e.preventDefault();
        openModal();
      });
    }
    document.addEventListener('keydown', onKeydown);
    // Initial load directly on the Billboard tab (the tab handler ran before
    // this module was parsed).
    var billboardPanel = document.getElementById('panel-billboard');
    if (billboardPanel && !billboardPanel.hasAttribute('hidden')) prime();
    // The catalog language can change while the modal is open.
    var langButtons = document.querySelectorAll('.lang-btn[data-lang]');
    for (var j = 0; j < langButtons.length; j++) {
      langButtons[j].addEventListener('click', function () {
        if (_overlay && !_overlay.hidden) setTimeout(function () { render(activePayload()); }, 0);
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
  } else {
    wire();
  }

  global.SPIDDailyMarketStory = {
    open: openModal,
    close: closeModal,
    prime: prime,
    refresh: function () { refreshNow(true); }
  };
})(window);
