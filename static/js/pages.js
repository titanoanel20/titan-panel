/* ============================================================
   TiTaN — pages: dashboard, users, configs, nodes,
   subscriptions, reports, settings, admins, tools
   ============================================================ */
(() => {
  'use strict';
  const U = window.UI;
  const { $, $$, esc, ICONS } = U;

  // ---------------- shared bits ----------------
  const PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard'];
  const TRANSPORTS = ['ws', 'xhttp', 'grpc', 'tcp', 'httpupgrade'];
  const FINGERPRINTS = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized'];
  const ALPNS = ['http/1.1', 'h2,http/1.1', 'h3,h2,http/1.1', ''];
  const SS_METHODS = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'];
  // Protocols that have no transport/security concept in the UI.
  const PROTO_NO_NET = { hysteria2: true, wireguard: true };

  function flagFor(cc) {
    cc = (cc || '').toUpperCase().trim();
    if (/^[A-Z]{2}$/.test(cc)) return String.fromCodePoint(...[...cc].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
    return '🏳️';
  }

  // Country flag for a node: SVG image (renders on every OS) with emoji fallback.
  function flagHtml(n, cls = '') {
    const cc = ((n && n.country_code) || '').toString().trim();
    const emoji = (n && n.flag) || flagFor(cc) || '🌐';
    if (/^[A-Za-z]{2}$/.test(cc)) {
      const lc = cc.toLowerCase();
      return `<span class="flag-wrap ${cls}"><img class="flag-img" src="https://flagcdn.com/w40/${lc}.png" srcset="https://flagcdn.com/w80/${lc}.png 2x" alt="${esc(cc.toUpperCase())}" loading="lazy" onerror="this.parentNode.classList.add('no-img')"><span class="flag-emoji">${esc(emoji)}</span></span>`;
    }
    return `<span class="flag ${cls}">${esc(emoji)}</span>`;
  }

  // Emoji flag for plain-text contexts (e.g. <option>).
  function flagEmoji(n) {
    const cc = ((n && n.country_code) || '').toString().trim();
    const fromCc = flagFor(cc);
    if (fromCc !== '🏳️') return fromCc;
    return (n && n.flag) || '🌐';
  }

  // User's own profile picture (per-user avatar).
  function userAvatarHtml(u) {
    const url = (u && u.avatar_url) || avatarUrl((u && u.avatar) || '');
    return `<span class="user-avatar"><img src="${esc(url)}" alt="" loading="lazy"></span>`;
  }

  function protoTag(p) { return `<span class="tag">${esc((p || '').toUpperCase())}</span>`; }

  function badge(label, cls) {
    return `<span class="badge ${cls}"><span class="dot"></span>${esc(label)}</span>`;
  }
  function statusBadge(u) {
    const s = U.userStatusLabel(u);
    return badge(s.text, s.cls);
  }
  function nodeBadge(n) {
    const st = n.status || {};
    if (!n.enabled) return badge(I18N.t('disabled'), 'bad');
    return st.online ? badge(I18N.t('online'), 'ok') : badge(I18N.t('offline'), 'bad');
  }

  // Human-readable reason for an offline node (from the /health probe).
  function offlineReason(st) {
    const r = st.reason || '';
    if (r === 'no-address') return I18N.t('node_no_address');
    if (r.indexOf('http-') === 0) return 'HTTP ' + r.slice(5);
    if (r) return r;
    return I18N.t('offline');
  }

  // ---------------- avatar gallery ----------------
  function avatarUrl(key) {
    key = key || '';
    if (key.startsWith('gallery:')) return '/static/img/gallery/' + key.slice(8) + '.svg';
    if (key.startsWith('upload:')) return '/api/gallery-image/' + key.slice(7);
    return '/static/img/titan-avatar.svg';
  }

  // keep the topbar profile picture in sync after the admin changes it
  function syncTopbarAvatar(key) {
    const top = $('#adminAvatar');
    if (top) top.src = avatarUrl(key);
  }

  function openGalleryPicker(opts = {}) {
    return new Promise((resolve) => {
      let items = [];
      let sel = opts.current || '';
      // The picker is a stacked overlay: opening it must NOT destroy the
      // parent modal (U.modal() calls closeModal() on open, which would kill
      // the user/config form we opened the picker from).
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay gallery-overlay';
      overlay.innerHTML = `
        <div class="modal" role="dialog" aria-modal="true" aria-label="${esc(I18N.t('gallery_title'))}">
          <div class="m-head"><h3>${esc(I18N.t('gallery_title'))}</h3><button class="icon-btn" data-close>${ICONS.close}</button></div>
          <div class="m-body">
            <button type="button" class="btn sm" id="galLogo" style="margin-bottom:14px">${I18N.t('gallery_use_logo')}</button>
            <div class="gallery-grid" id="galGrid"></div>
            <div class="row" style="gap:8px;margin-top:16px">
              <button type="button" class="btn sm" id="galUploadBtn">${ICONS.upload}<span data-i18n="gallery_upload"></span></button>
              <input type="file" id="galFile" accept="image/png,image/jpeg,image/webp" class="hidden">
            </div>
          </div>
          <div class="m-foot">
            <button class="btn" data-close>${I18N.t('cancel')}</button>
            <button class="btn primary" id="galConfirm">${I18N.t('save')}</button>
          </div>
        </div>`;
      document.body.appendChild(overlay);
      const m = {
        el: overlay,
        query: (s) => overlay.querySelector(s),
        queryAll: (s) => Array.from(overlay.querySelectorAll(s)),
      };
      let done = false;
      const finish = (val) => {
        if (done) return;
        done = true;
        overlay.remove();
        document.removeEventListener('keydown', onKey);
        resolve(val);
      };
      const onKey = (e) => { if (e.key === 'Escape') finish(null); };
      document.addEventListener('keydown', onKey);

      const render = () => {
        const grid = m.query('#galGrid');
        const logoBtn = m.query('#galLogo');
        if (logoBtn) logoBtn.className = 'btn sm' + (sel === '' ? ' primary' : '');
        if (!grid) return;
        grid.innerHTML = items.length ? items.map(it => `
          <button type="button" class="gallery-item ${sel === it.id ? 'sel' : ''}" data-key="${esc(it.id)}" title="${esc(it.name)}">
            <img src="${esc(it.url)}" alt="">
            <span class="gallery-check">✓</span>
            ${!it.builtin ? `<span class="gallery-del" data-del="${esc(it.id)}">×</span>` : ''}
          </button>`).join('') : `<div class="cell-sub">${I18N.t('gallery_empty')}</div>`;
      };
      I18N.apply();
      render();
      (async () => {
        try { items = (await U.apiJson('/api/gallery')).items || []; } catch (_) { /* keep */ }
        render();
      })();

      m.query('#galLogo').addEventListener('click', () => { sel = ''; render(); });
      m.query('#galGrid').addEventListener('click', async (e) => {
        const del = e.target.closest('[data-del]');
        if (del) {
          const key = del.dataset.del;
          if (key.startsWith('upload:')) {
            try {
              await U.apiJson('/api/gallery/' + key.slice(7), { method: 'DELETE' });
              items = items.filter(i => i.id !== key);
              if (sel === key) sel = '';
              render();
            } catch (err) { U.toast(err.message, 'err'); }
          }
          return;
        }
        const item = e.target.closest('[data-key]');
        if (item) { sel = item.dataset.key; render(); }
      });
      m.query('#galUploadBtn').addEventListener('click', () => m.query('#galFile').click());
      m.query('#galFile').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const fd = new FormData(); fd.append('file', file);
        try {
          const r = await fetch('/api/gallery', { method: 'POST', body: fd });
          const d = await r.json().catch(() => ({}));
          if (r.ok) { items.push(d.item); sel = d.item.id; render(); }
          else U.toast(d.detail || I18N.t('error'), 'err');
        } catch (_) { U.toast(I18N.t('error'), 'err'); }
        e.target.value = '';
      });
      m.query('#galConfirm').addEventListener('click', () => finish(sel));
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay || e.target.closest('[data-close]')) finish(null);
      });
    });
  }

  function avatarPickerHtml(initialKey) {
    return `
      <div class="row" style="gap:14px;align-items:center">
        <img class="avatar-preview av-pick-preview" src="${esc(avatarUrl(initialKey))}" alt="avatar">
        <input type="hidden" name="avatar" value="${esc(initialKey || '')}">
        <button type="button" class="btn sm av-pick-btn">${ICONS.link}<span data-i18n="gallery_choose"></span></button>
      </div>`;
  }

  function wireAvatarPicker(rootEl) {
    const btn = rootEl.querySelector('.av-pick-btn');
    const input = rootEl.querySelector('input[name="avatar"]');
    const preview = rootEl.querySelector('.av-pick-preview');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      const key = await openGalleryPicker({ current: input.value });
      if (key == null) return;
      input.value = key;
      preview.src = avatarUrl(key);
    });
  }

  // Protocols like Hysteria2/WireGuard have no transport/security pickers —
  // disable them. Shadowsocks shows a method picker instead.
  function wireProtoDeps(rootEl) {
    const pSel = rootEl.querySelector('select[name="protocol"]');
    const tSel = rootEl.querySelector('select[name="transport"]');
    const sSel = rootEl.querySelector('select[name="security"]');
    const ssSel = rootEl.querySelector('select[name="ss_method"]');
    const ssField = ssSel ? ssSel.closest('.field') : null;
    if (!pSel) return;
    const apply = () => {
      const p = pSel.value;
      const noNet = !!PROTO_NO_NET[p];
      if (tSel) tSel.disabled = noNet;
      if (sSel) sSel.disabled = noNet;
      if (ssField) ssField.style.display = (p === 'shadowsocks') ? '' : 'none';
    };
    pSel.addEventListener('change', apply);
    apply();
  }

  // Node picker with an "auto (nearest)" option (value 0).
  function nodeOptionsHtml(nodes, sel, withLocation) {
    const cur = (sel == null || sel === '') ? (nodes[0] ? nodes[0].id : 0) : Number(sel);
    const auto = `<option value="0" ${cur === 0 ? 'selected' : ''}>🌐 ${I18N.t('node_auto')}</option>`;
    return auto + nodes.map(n => {
      const loc = withLocation ? ' — ' + esc(n.city !== '—' ? n.city : n.country) : '';
      return `<option value="${n.id}" ${cur === n.id ? 'selected' : ''}>${esc(flagEmoji(n))} ${esc(n.name)}${loc}</option>`;
    }).join('');
  }

  // Node label for a user row (handles node_id=0 → "auto").
  function nodeNameHtml(u, nodeMap) {
    if (Number(u && u.node_id) === 0) return `<span class="node-inline">🌐<span>${I18N.t('node_auto')}</span></span>`;
    const n = nodeMap[(u && u.node_id) || 1];
    if (!n) return '—';
    const nm = (n.city && n.city !== '—') ? n.city : n.name;
    return `<span class="node-inline">${flagHtml(n, 'flag-sm')}<span>${esc(nm)}</span></span>`;
  }

  // ---------------- form field builders ----------------
  function userFields(u, settings, nodes) {
    const s = settings || {};
    const sel = (name, opts, val) => opts.map(o =>
      `<option value="${o}" ${String(val) === o ? 'selected' : ''}>${esc(o || '—')}</option>`).join('');
    return `
      <div class="field full">
        <span class="field-label" data-i18n="avatar_user"></span>
        ${avatarPickerHtml(u?.avatar || '')}
      </div>
      <div class="grid-form">
        <label class="field"><span class="field-label" data-i18n="name"></span>
          <input class="input" name="name" value="${esc(u?.name || '')}" required></label>
        <label class="field"><span class="field-label" data-i18n="protocol"></span>
          <select class="select" name="protocol">${PROTOCOLS.map(p => `<option value="${p}" ${(u?.protocol || 'vless') === p ? 'selected' : ''}>${p.toUpperCase()}</option>`).join('')}</select></label>
        <label class="field"><span class="field-label" data-i18n="transport"></span>
          <select class="select" name="transport">${TRANSPORTS.map(t => `<option value="${t}" ${(u?.transport || s.default_transport || 'ws') === t ? 'selected' : ''}>${t.toUpperCase()}</option>`).join('')}</select></label>
        <label class="field"><span class="field-label" data-i18n="security"></span>
          <select class="select" name="security">
            <option value="tls" ${(u?.security || 'tls') === 'tls' ? 'selected' : ''}>TLS</option>
            <option value="none" ${u?.security === 'none' ? 'selected' : ''}>None</option>
            <option value="reality" ${u?.security === 'reality' ? 'selected' : ''}>Reality</option>
          </select></label>
        <label class="field"><span class="field-label" data-i18n="fingerprint"></span>
          <select class="select" name="fingerprint">${sel('fingerprint', FINGERPRINTS, u?.fingerprint || s.default_fingerprint || 'chrome')}</select></label>
        <label class="field"><span class="field-label" data-i18n="alpn"></span>
          <select class="select" name="alpn">${sel('alpn', ALPNS, u?.alpn ?? s.default_alpn ?? 'http/1.1')}</select></label>
        <label class="field"><span class="field-label" data-i18n="quota_gb"></span>
          <input class="input" type="number" step="0.1" min="0" name="quota_gb" value="${u?.quota_gb || 0}"></label>
        <label class="field"><span class="field-label" data-i18n="expire_days"></span>
          <input class="input" type="number" min="0" name="expire_days" value="${u?.expire_at ? Math.max(0, Math.ceil((u.expire_at - Date.now() / 1000) / 86400)) : 0}"></label>
        <label class="field"><span class="field-label" data-i18n="max_devices"></span>
          <input class="input" type="number" min="0" name="max_devices" value="${u?.max_devices || 0}"></label>
        <label class="field"><span class="field-label" data-i18n="max_requests"></span>
          <input class="input" type="number" min="0" name="max_requests" value="${u?.max_requests || 0}"></label>
        <label class="field" style="display:none"><span class="field-label" data-i18n="ss_method"></span>
          <select class="select" name="ss_method">${SS_METHODS.map(m => `<option value="${m}" ${(u?.ss_method || s.ss_method || '2022-blake3-aes-128-gcm') === m ? 'selected' : ''}>${m}</option>`).join('')}</select></label>
        ${nodes ? `<label class="field"><span class="field-label" data-i18n="select_node"></span>
          <select class="select" name="node_id">${nodeOptionsHtml(nodes, u?.node_id, false)}</select></label>` : ''}
        <label class="field full"><span class="field-label" data-i18n="allowed_ips"></span>
          <input class="input" name="allowed_ips" value="${esc((u?.allowed_ips || []).join(','))}" dir="ltr"></label>
        <label class="field full"><span class="field-label" data-i18n="note"></span>
          <textarea class="input" name="note" rows="2">${esc(u?.note || '')}</textarea></label>
      </div>`;
  }

  function collectUserForm(formEl) {
    const fd = new FormData(formEl);
    return {
      name: fd.get('name'), protocol: fd.get('protocol'), transport: fd.get('transport'),
      security: fd.get('security'), fingerprint: fd.get('fingerprint'), alpn: fd.get('alpn'),
      ss_method: fd.get('ss_method'),
      quota_gb: parseFloat(fd.get('quota_gb')) || 0,
      expire_days: parseInt(fd.get('expire_days')) || 0,
      max_devices: parseInt(fd.get('max_devices')) || 0,
      max_requests: parseInt(fd.get('max_requests')) || 0,
      node_id: fd.get('node_id') ? parseInt(fd.get('node_id')) : undefined,
      allowed_ips: (fd.get('allowed_ips') || '').split(',').map(s => s.trim()).filter(Boolean),
      note: fd.get('note'),
      avatar: fd.get('avatar') || '',
    };
  }

  // ---------------- links / qr modals ----------------
  async function openLinksModal(uid) {
    const d = await U.apiJson(`/api/users/${uid}/links`);
    const linkRow = (lbl, val) => `
      <div style="margin-bottom:14px">
        <div class="muted" style="font-size:.78rem;color:var(--text-3);margin-bottom:6px">${esc(lbl)}</div>
        <div class="row" style="gap:8px">
          <input class="input" style="direction:ltr;font-family:monospace;font-size:.76rem;flex:1" readonly value="${esc(val)}">
          <button class="btn sm" data-copy="${esc(val)}">${ICONS.copy}</button>
        </div>
      </div>`;
    let wgBlock = '';
    if (d.protocol === 'wireguard') {
      let conf = '';
      try { conf = (await U.apiJson(`/api/users/${uid}/wireguard`)).conf || ''; } catch (_) { /* keep */ }
      wgBlock = `
        <div style="margin:14px 0;padding:12px;border:1px solid var(--border);border-radius:12px">
          <div class="row" style="justify-content:space-between;align-items:center;margin-bottom:8px">
            <span class="field-label" data-i18n="wg_config"></span>
            <a class="btn sm primary" href="/api/users/${uid}/wireguard.conf" download>${ICONS.download}<span data-i18n="wg_download"></span></a>
          </div>
          <textarea class="input" rows="9" dir="ltr" readonly style="font-family:monospace;font-size:.72rem">${esc(conf)}</textarea>
        </div>`;
    }
    U.modal({
      title: I18N.t('links') + ' — ' + esc(d.name || uid),
      body: `
        ${(d.links || []).map(l => linkRow((l.split('://')[0] || '').toUpperCase(), l)).join('')}
        ${linkRow(I18N.t('sub_link'), d.sub_url)}
        ${linkRow('Status URL', d.status_url)}
        ${wgBlock}
        <div style="text-align:center;margin-top:10px">
          <img src="/api/users/${uid}/qr" style="max-width:200px;border-radius:12px;border:1px solid var(--border)" alt="QR">
        </div>`,
      foot: `<button class="btn" data-close>${I18N.t('close')}</button>`,
    });
    U.$$('[data-copy]').forEach(b => b.addEventListener('click', () => U.copyText(b.dataset.copy)));
    I18N.apply();
  }

  // ================================================================ dashboard
  async function dashboard(view) {
    view.innerHTML = `
      <section class="dashboard">
        <div id="dashBanners"></div>
        <div class="stats-grid" id="statGrid">
          ${['gold', 'green', 'blue', 'purple'].map(() => `<div class="stat-card">${U.skeleton(2)}</div>`).join('')}
        </div>

        <div class="middle-grid">
          <div class="panel chart-panel">
            <div class="panel-header">
              <div>
                <div class="panel-title" data-i18n="chart_traffic"></div>
                <div class="panel-subtitle" data-i18n="chart_sub_7d"></div>
              </div>
            </div>
            <div class="chart-wrap" id="trafficChart">${U.skeleton(6)}</div>
          </div>

          <div class="panel servers-panel">
            <div class="panel-header">
              <div class="panel-title" data-i18n="server_status"></div>
              <div class="panel-tools">
                <button class="tool-btn" id="serversRefresh" aria-label="refresh">↻</button>
                <button class="tool-btn" id="serversToggle" aria-label="collapse">×</button>
              </div>
            </div>
            <div class="server-list" id="nodeList">${U.skeleton(5)}</div>
            <a href="#/nodes" class="view-all" data-i18n="view_all_servers"></a>
          </div>
        </div>

        <div class="bottom-grid">
          <div class="panel bottom-panel">
            <div class="table-header">
              <div class="table-title" data-i18n="recent_users"></div>
              <a href="#/users" class="table-link" data-i18n="view_all"></a>
            </div>
            <div class="users-table" id="recentUsers">${U.skeleton(3)}</div>
          </div>

          <div class="panel bottom-panel">
            <div class="table-header">
              <div class="table-title" data-i18n="latest_configs"></div>
              <a href="#/configs" class="table-link" data-i18n="view_all"></a>
            </div>
            <div class="config-table" id="latestConfigs">${U.skeleton(3)}</div>
          </div>
        </div>
      </section>`;
    I18N.apply();

    const badgeOf = (u) => {
      const st = U.userStatusLabel(u);
      const cls = st.cls === 'ok' ? 'active' : (st.cls === 'warn' ? 'expired' : 'inactive');
      return `<span class="badge ${cls}">${esc(st.text)}</span>`;
    };

    async function load() {
      const [stats, reports, nodesRes, usersRes, settings] = await Promise.all([
        U.apiJson('/api/stats'),
        U.apiJson('/api/reports?days=7'),
        U.apiJson('/api/nodes'),
        U.apiJson('/api/users'),
        U.apiJson('/api/settings'),
      ]);

      // connectivity banners (real xray + domain state)
      const banners = [];
      if (!stats.xray_installed) banners.push(['err', I18N.t('xray_not_installed_banner')]);
      else if (!stats.xray_running) banners.push(['warn', I18N.t('xray_down_banner')]);
      if (!(settings.public_domain || '').trim()) banners.push(['info', I18N.t('domain_not_set_banner')]);
      $('#dashBanners').innerHTML = banners.map(b =>
        `<div class="banner ${b[0]}"><span class="banner-dot"></span><span>${esc(b[1])}</span></div>`).join('');

      const nodes = nodesRes.nodes || [];
      const users = usersRes.users || [];
      const online = nodes.filter(n => n.enabled && n.status && n.status.online).length;
      const totalTraffic = (stats.total_up || 0) + (stats.total_down || 0);
      const nowSec = Date.now() / 1000;
      const activeUsers = users.filter(u =>
        (u.last_seen && (nowSec - u.last_seen) < 86400) ||
        ((u.status || {}).active_connections || 0) > 0).length;

      // stat cards — v2 order & variants: gold, green, blue, purple
      const cards = [
        { color: 'gold', icon: '▣', label: 'stat_configs', value: stats.enabled_count, change: I18N.t('stat_configs_sub', { n: stats.users_count }) },
        { color: 'green', icon: '▤', label: 'stat_servers', value: stats.nodes_count, change: `<strong>● ${online} ${I18N.t('online')}</strong>` },
        { color: 'blue', icon: '↔', label: 'stat_traffic', value: U.fmtBytes(totalTraffic), change: I18N.t('stat_traffic_sub', { up: U.fmtBytes(stats.total_up), down: U.fmtBytes(stats.total_down) }) },
        { color: 'purple', icon: '♙', label: 'stat_active_users', value: activeUsers, change: I18N.t('stat_users_sub', { n: stats.users_count }) },
      ];
      $('#statGrid').innerHTML = cards.map(c => `
        <div class="stat-card ${c.color}">
          <div class="stat-title" data-i18n="${c.label}"></div>
          <div class="stat-value">${esc(String(c.value))}</div>
          <div class="stat-change">${c.change}</div>
          <div class="stat-icon">${c.icon}</div>
        </div>`).join('');

      // traffic chart (7 days, Persian day labels)
      const daily = (reports.daily || []).slice(-7);
      if (daily.some(d => d.up || d.down)) {
        const xlabels = daily.map((_, i) => {
          const ago = daily.length - 1 - i;
          return ago === 0 ? I18N.t('today') : I18N.t('days_ago', { n: ago });
        });
        U.drawChart('#trafficChart', daily, { daily: true, xlabels });
      } else {
        $('#trafficChart').innerHTML = U.empty('📊', I18N.t('empty_traffic'), '');
      }

      // server status list (real nodes)
      $('#nodeList').innerHTML = nodes.length ? nodes.slice(0, 5).map(n => {
        const st = n.status || {};
        const isOn = n.enabled && st.online;
        const city = (n.city && n.city !== '—') ? n.city : (n.name || '—');
        return `
          <div class="server-row">
            <div class="server-name">${flagHtml(n)}${esc(city)}</div>
            <div class="country-code">${esc((n.country_code || '').toUpperCase()) || '—'}</div>
            <div class="server-status ${isOn ? '' : 'offline'}"><span>${isOn ? I18N.t('online') : I18N.t('offline')}</span></div>
            <div class="ping">${isOn && st.latency_ms != null ? st.latency_ms + 'ms' : '-'}</div>
          </div>`;
      }).join('') : U.empty('🖥️', I18N.t('no_nodes'), '');

      // recent users (real, newest first)
      const headUsers = `<div class="user-table-head"><div data-i18n="user"></div><div data-i18n="traffic_used"></div><div data-i18n="status"></div></div>`;
      const recent = [...users].sort((a, b) => (b.created_at || 0) - (a.created_at || 0)).slice(0, 3);
      $('#recentUsers').innerHTML = recent.length ? headUsers + recent.map(u => `
        <div class="user-row">
          <div class="user-cell"><div class="user-info">${userAvatarHtml(u)}${esc(u.name)}</div></div>
          <div class="user-cell traffic">${U.fmtBytes((u.status || {}).used || 0)}</div>
          <div class="user-cell">${badgeOf(u)}</div>
        </div>`).join('') : U.empty('👤', I18N.t('no_users'), '');

      // latest configs (real, newest first)
      const nodeMap = {};
      nodes.forEach(n => { nodeMap[n.id] = n; });
      const headCfgs = `<div class="config-head"><div data-i18n="name"></div><div data-i18n="type"></div><div data-i18n="node"></div><div data-i18n="status"></div></div>`;
      const latest = [...users].sort((a, b) => (b.created_at || 0) - (a.created_at || 0)).slice(0, 3);
      $('#latestConfigs').innerHTML = latest.length ? headCfgs + latest.map(u => {
        const n = nodeMap[u.node_id || 1];
        const nCell = Number(u.node_id) === 0
          ? '<span class="config-node-name">🌐 ' + I18N.t('node_auto') + '</span>'
          : (n ? flagHtml(n, 'flag-sm') + '<span class="config-node-name">' + esc((n.city && n.city !== '—') ? n.city : n.name) + '</span>' : '—');
        return `
        <div class="config-row">
          <div class="config-cell config-name"><div class="u-inline">${userAvatarHtml(u)}<span>${esc(u.name)}</span></div></div>
          <div class="config-cell">${esc((u.protocol || '').toUpperCase())}</div>
          <div class="config-cell">${nCell}</div>
          <div class="config-cell config-status">${badgeOf(u)}</div>
        </div>`;
      }).join('') : U.empty('⚙️', I18N.t('no_configs'), '');

      I18N.apply();
    }

    try {
      await load();
    } catch (e) {
      view.innerHTML = U.empty('⚠️', I18N.t('error'), e.message || '');
      return;
    }

    $('#serversRefresh').addEventListener('click', async () => {
      const b = $('#serversRefresh');
      b.classList.add('spin');
      try { await load(); } catch (_) { /* noop */ }
      setTimeout(() => b.classList.remove('spin'), 550);
    });
    $('#serversToggle').addEventListener('click', () => {
      document.querySelector('.servers-panel').classList.toggle('collapsed');
    });
  }

  // ================================================================ users
  async function users(view) {
    view.innerHTML = `
      <div class="page-head">
        <div><h1 class="page-title" data-i18n="users_title"></h1><p class="page-sub" data-i18n="users_sub"></p></div>
        <div class="page-actions"><button class="btn primary" id="addUserBtn">${ICONS.plus}<span data-i18n="add_user"></span></button></div>
      </div>
      <div class="toolbar">
        <input class="input grow" id="usersSearch" data-i18n-ph="search" style="max-width:320px">
        <select class="select" id="usersStatusFilter"><option value="" data-i18n="filter_status"></option><option value="enabled" data-i18n="enabled"></option><option value="expired" data-i18n="expired"></option><option value="disabled" data-i18n="disabled"></option></select>
        <select class="select" id="usersProtoFilter"><option value="" data-i18n="filter_protocol"></option>${PROTOCOLS.map(p => `<option value="${p}">${p.toUpperCase()}</option>`).join('')}</select>
      </div>
      <div class="table-wrap">
        <table class="data">
          <thead><tr>
            <th data-i18n="user"></th><th data-i18n="protocol"></th>
            <th class="num" data-i18n="traffic_used"></th><th data-i18n="expiry"></th>
            <th data-i18n="status"></th><th data-i18n="actions"></th>
          </tr></thead>
          <tbody id="usersRows"><tr><td colspan="6">${U.skeleton(8)}</td></tr></tbody>
        </table>
      </div>
      <div class="pager" id="usersPager"></div>`;

    let all = [];
    let page = 0;
    const SIZE = 8;

    async function load() {
      try { all = (await U.apiJson('/api/users')).users || []; }
      catch (e) { $('#usersRows').innerHTML = `<tr><td colspan="6">${U.empty('⚠️', I18N.t('error'), e.message)}</td></tr>`; return; }
      draw();
    }
    function draw() {
      const q = ($('#usersSearch').value || '').toLowerCase();
      const sf = $('#usersStatusFilter').value;
      const pf = $('#usersProtoFilter').value;
      let list = all.filter(u => (u.name + (u.note || '')).toLowerCase().includes(q));
      if (pf) list = list.filter(u => u.protocol === pf);
      if (sf) {
        list = list.filter(u => {
          const st = u.status || {};
          if (sf === 'expired') return st.expired;
          if (sf === 'disabled') return !u.enabled && !st.expired;
          return u.enabled && st.live_enabled;
        });
      }
      const pages = Math.max(1, Math.ceil(list.length / SIZE));
      page = Math.min(page, pages - 1);
      const slice = list.slice(page * SIZE, page * SIZE + SIZE);
      const tbody = $('#usersRows');
      if (!list.length) {
        tbody.innerHTML = `<tr><td colspan="6">${U.empty('👤', I18N.t('no_users'), I18N.t('no_users_sub'))}</td></tr>`;
      } else {
        tbody.innerHTML = slice.map(u => `
          <tr>
            <td><div class="cell-main"><div class="u-inline">${userAvatarHtml(u)}<span class="cell-title">${esc(u.name)}</span></div><span class="cell-sub">${esc(u.note || '')}</span></div></td>
            <td>${protoTag(u.protocol)}</td>
            <td class="num"><div>${U.fmtBytes((u.status || {}).used || 0)} <span class="cell-sub">/ ${u.quota_gb > 0 ? u.quota_gb + ' GB' : I18N.t('unlimited')}</span></div>${U.usageBar(u)}</td>
            <td>${u.expire_at ? U.fmtDate(u.expire_at) : `<span class="cell-sub">${I18N.t('never')}</span>`}</td>
            <td>${statusBadge(u)}</td>
            <td>
              <div class="row-actions">
                <button class="icon-btn" data-act="links" data-uid="${u.uid}" title="${I18N.t('links')}">${ICONS.link}</button>
                <button class="icon-btn" data-act="toggle" data-uid="${u.uid}" title="${I18N.t('toggle')}">${ICONS.power}</button>
                <button class="icon-btn" data-act="reset" data-uid="${u.uid}" title="${I18N.t('reset_usage')}">${ICONS.refresh}</button>
                <button class="icon-btn" data-act="edit" data-uid="${u.uid}" title="${I18N.t('edit')}">${ICONS.edit}</button>
                <button class="icon-btn" data-act="delete" data-uid="${u.uid}" title="${I18N.t('delete')}">${ICONS.trash}</button>
              </div>
            </td>
          </tr>`).join('');
      }
      // pager
      $('#usersPager').innerHTML = pages > 1 ? `
        <button class="btn sm" id="pgPrev" ${page === 0 ? 'disabled' : ''}>${I18N.t('prev')}</button>
        <span class="cell-sub">${page + 1} / ${pages}</span>
        <button class="btn sm" id="pgNext" ${page >= pages - 1 ? 'disabled' : ''}>${I18N.t('next')}</button>` : '';
      const prev = $('#pgPrev'), next = $('#pgNext');
      if (prev) prev.onclick = () => { page--; draw(); };
      if (next) next.onclick = () => { page++; draw(); };
      I18N.apply();
    }

    $('#usersSearch').addEventListener('input', U.debounce(() => { page = 0; draw(); }, 250));
    $('#usersStatusFilter').addEventListener('change', () => { page = 0; draw(); });
    $('#usersProtoFilter').addEventListener('change', () => { page = 0; draw(); });
    $('#usersRows').addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-act]');
      if (!btn) return;
      const uid = btn.dataset.uid;
      if (!uid) return;
      const act = btn.dataset.act;
      const needReload = ['toggle', 'reset', 'delete'].includes(act);
      await userAction(uid, act);
      if (needReload) await load();
      else if (U.current === 'users') U.render();
    });

    $('#addUserBtn').addEventListener('click', () => openUserForm(null));
    await load();
    I18N.apply();
  }

  async function userAction(uid, act) {
    try {
      if (act === 'toggle') { await U.apiJson(`/api/users/${uid}/toggle`, { method: 'POST' }); U.toast('ok', 'ok'); }
      else if (act === 'links') { await openLinksModal(uid); }
      else if (act === 'reset') { await U.apiJson(`/api/users/${uid}/reset`, { method: 'POST' }); U.toast('ok', 'ok'); }
      else if (act === 'edit') { const d = await U.apiJson(`/api/users/${uid}`); openUserForm(d); }
      else if (act === 'delete') {
        if (await U.confirmDlg(I18N.t('delete'), I18N.t('delete_confirm_user'))) {
          await U.apiJson(`/api/users/${uid}`, { method: 'DELETE' }); U.toast('ok', 'ok');
        }
      }
    } catch (err) { U.toast(err.message, 'err'); }
  }

  async function openUserForm(u) {
    const [settings, nodesRes] = await Promise.all([
      U.apiJson('/api/settings'),
      U.apiJson('/api/nodes').catch(() => ({ nodes: [] })),
    ]);
    const nodes = nodesRes.nodes || [];
    const m = U.modal({
      title: I18N.t(u ? 'edit' : 'add_user'),
      lg: true,
      body: `<form id="userForm">${userFields(u, settings, nodes)}</form>`,
      foot: `<button class="btn" data-close>${I18N.t('cancel')}</button>
             <button class="btn primary" id="saveUserBtn">${I18N.t('save')}</button>`,
    });
    wireAvatarPicker(m.query('#userForm'));
    wireProtoDeps(m.query('#userForm'));
    I18N.apply();
    m.query('#saveUserBtn').addEventListener('click', async () => {
      const body = collectUserForm(m.query('#userForm'));
      try {
        if (u) { await U.apiJson(`/api/users/${u.uid}`, { method: 'PATCH', body: JSON.stringify(body) }); }
        else { await U.apiJson('/api/users', { method: 'POST', body: JSON.stringify(body) }); }
        U.closeModal();
        U.toast(I18N.t(u ? 'user_updated' : 'user_created'), 'ok');
        if (U.current === 'users') U.render();
      } catch (err) { U.toast(err.message, 'err'); }
    });
  }

  // ================================================================ configs
  async function configs(view) {
    view.innerHTML = `
      <div class="page-head">
        <div><h1 class="page-title" data-i18n="configs_title"></h1><p class="page-sub" data-i18n="configs_sub"></p></div>
        <div class="page-actions"><button class="btn primary" id="newConfigBtn">${ICONS.plus}<span data-i18n="new_config"></span></button></div>
      </div>
      <div class="toolbar">
        <input class="input grow" id="cfgSearch" data-i18n-ph="search" style="max-width:320px">
        <select class="select" id="cfgStatusFilter"><option value="" data-i18n="filter_status"></option><option value="enabled" data-i18n="enabled"></option><option value="expired" data-i18n="expired"></option><option value="disabled" data-i18n="disabled"></option></select>
        <select class="select" id="cfgProtoFilter"><option value="" data-i18n="filter_protocol"></option>${PROTOCOLS.map(p => `<option value="${p}">${p.toUpperCase()}</option>`).join('')}</select>
      </div>
      <div class="table-wrap">
        <table class="data">
          <thead><tr>
            <th data-i18n="status"></th><th data-i18n="name"></th><th data-i18n="node"></th>
            <th data-i18n="protocol"></th><th data-i18n="created"></th><th data-i18n="expiry"></th>
            <th class="num" data-i18n="traffic_used"></th><th data-i18n="actions"></th>
          </tr></thead>
          <tbody id="cfgRows"><tr><td colspan="8">${U.skeleton(8)}</td></tr></tbody>
        </table>
      </div>`;

    let users = [], nodes = [];
    async function load() {
      try {
        [users, nodes] = await Promise.all([
          U.apiJson('/api/users').then(d => d.users || []),
          U.apiJson('/api/nodes').then(d => d.nodes || []),
        ]);
      } catch (e) { $('#cfgRows').innerHTML = `<tr><td colspan="8">${U.empty('⚠️', I18N.t('error'), e.message)}</td></tr>`; return; }
      draw();
    }
    const nodeMap = () => { const m = {}; nodes.forEach(n => m[n.id] = n); return m; };
    function draw() {
      const q = ($('#cfgSearch').value || '').toLowerCase();
      const sf = $('#cfgStatusFilter').value, pf = $('#cfgProtoFilter').value;
      const nm = nodeMap();
      let list = users.filter(u => (u.name + (u.note || '')).toLowerCase().includes(q));
      if (pf) list = list.filter(u => u.protocol === pf);
      if (sf) list = list.filter(u => {
        const st = u.status || {};
        if (sf === 'expired') return st.expired;
        if (sf === 'disabled') return !u.enabled && !st.expired;
        return u.enabled && st.live_enabled;
      });
      $('#cfgRows').innerHTML = list.length ? list.map(u => {
        return `<tr>
          <td>${statusBadge(u)}</td>
          <td><div class="cell-main"><div class="u-inline">${userAvatarHtml(u)}<span class="cell-title">${esc(u.name)}</span></div><span class="cell-sub">${esc(u.note || '')}</span></div></td>
          <td>${nodeNameHtml(u, nm)}</td>
          <td>${protoTag(u.protocol)}</td>
          <td>${U.fmtDate(u.created_at)}</td>
          <td>${u.expire_at ? U.fmtDate(u.expire_at) : `<span class="cell-sub">${I18N.t('never')}</span>`}</td>
          <td class="num">${U.fmtBytes((u.status || {}).used || 0)}</td>
          <td>
            <div class="row-actions">
              <button class="icon-btn" data-act="links" data-uid="${u.uid}" title="${I18N.t('links')}">${ICONS.link}</button>
              <button class="icon-btn" data-act="edit" data-uid="${u.uid}" title="${I18N.t('edit')}">${ICONS.edit}</button>
              <button class="icon-btn" data-act="toggle" data-uid="${u.uid}" title="${I18N.t('toggle')}">${ICONS.power}</button>
              <button class="icon-btn" data-act="delete" data-uid="${u.uid}" title="${I18N.t('delete')}">${ICONS.trash}</button>
            </div>
          </td>
        </tr>`;
      }).join('') : `<tr><td colspan="8">${U.empty('⚙️', I18N.t('no_configs'), '')}</td></tr>`;
    }
    $('#cfgSearch').addEventListener('input', U.debounce(draw, 250));
    $('#cfgStatusFilter').addEventListener('change', draw);
    $('#cfgProtoFilter').addEventListener('change', draw);
    $('#cfgRows').addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-act]');
      if (!btn) return;
      const uid = btn.dataset.uid, act = btn.dataset.act;
      if (act === 'links') { await openLinksModal(uid); }
      else if (act === 'edit') { const d = await U.apiJson(`/api/users/${uid}`); openConfigWizard(d, nodes); }
      else if (act === 'toggle') { await U.apiJson(`/api/users/${uid}/toggle`, { method: 'POST' }); await load(); }
      else if (act === 'delete') {
        if (await U.confirmDlg(I18N.t('delete'), I18N.t('delete_confirm_user'))) { await U.apiJson(`/api/users/${uid}`, { method: 'DELETE' }); await load(); }
      }
    });
    $('#newConfigBtn').addEventListener('click', async () => {
      // reuse the node list already loaded for this page (avoids a second
      // /api/nodes round-trip and its status probes); fall back to fetching.
      let list = nodes;
      if (!list.length) {
        try { list = (await U.apiJson('/api/nodes')).nodes || []; } catch (_) { list = []; }
      }
      openConfigWizard(null, list);
    });
    await load();
    I18N.apply();
  }

  async function openConfigWizard(u, nodes) {
    const settings = await U.apiJson('/api/settings');
    const preview = () => {
      const f = m.query('#cfgForm');
      if (!f) return;
      const v = collectUserForm(f);
      const n = nodes.find(x => x.id === v.node_id);
      const nodeLabel = v.node_id === 0 ? '🌐 ' + I18N.t('node_auto') : (n ? flagHtml(n, 'flag-sm') + ' ' + esc(n.name) : '—');
      $('#cfgPreview').innerHTML = `
        <div class="row" style="gap:8px;margin-bottom:8px"><span class="tag">${esc((v.protocol || '').toUpperCase())}</span><span class="tag">${esc((v.transport || '').toUpperCase())}</span><span class="tag">${esc(v.security || '')}</span></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:.82rem">
          <div><span class="cell-sub">${I18N.t('name')}:</span> ${esc(v.name || '—')}</div>
          <div><span class="cell-sub">${I18N.t('node')}:</span> ${nodeLabel}</div>
          <div><span class="cell-sub">${I18N.t('quota')}:</span> ${v.quota_gb > 0 ? v.quota_gb + ' GB' : I18N.t('unlimited')}</div>
          <div><span class="cell-sub">${I18N.t('expiry')}:</span> ${v.expire_days > 0 ? v.expire_days + ' ' + I18N.t('rep_days_7').replace('۷','') + '' : I18N.t('never')}</div>
        </div>`;
    };
    const m = U.modal({
      title: I18N.t(u ? 'edit' : 'new_config'),
      lg: true,
      body: `
        <form id="cfgForm">
          <div class="wiz-section"><h4><span class="step">1</span>${I18N.t('wizard_main')}</h4>
            <div class="field">
              <span class="field-label" data-i18n="avatar_user"></span>
              ${avatarPickerHtml(u?.avatar || '')}
            </div>
            <div class="grid-form">
              <label class="field"><span class="field-label" data-i18n="config_name"></span><input class="input" name="name" value="${esc(u?.name || '')}" required></label>
              <label class="field"><span class="field-label" data-i18n="note"></span><input class="input" name="note" value="${esc(u?.note || '')}"></label>
            </div>
          </div>
          <div class="wiz-section"><h4><span class="step">2</span>${I18N.t('wizard_server')}</h4>
            <label class="field"><span class="field-label" data-i18n="select_node"></span>
              <select class="select" name="node_id">${nodeOptionsHtml(nodes, u?.node_id, true)}</select>
            </label>
          </div>
          <div class="wiz-section"><h4><span class="step">3</span>${I18N.t('wizard_network')}</h4>
            <div class="grid-form">
              <label class="field"><span class="field-label" data-i18n="protocol"></span>
                <select class="select" name="protocol">${PROTOCOLS.map(p => `<option value="${p}" ${(u?.protocol || 'vless') === p ? 'selected' : ''}>${p.toUpperCase()}</option>`).join('')}</select></label>
              <label class="field"><span class="field-label" data-i18n="transport"></span>
                <select class="select" name="transport">${TRANSPORTS.map(t => `<option value="${t}" ${(u?.transport || settings.default_transport || 'ws') === t ? 'selected' : ''}>${t.toUpperCase()}</option>`).join('')}</select></label>
              <label class="field" style="display:none"><span class="field-label" data-i18n="ss_method"></span>
                <select class="select" name="ss_method">${SS_METHODS.map(m => `<option value="${m}" ${(u?.ss_method || settings.ss_method || '2022-blake3-aes-128-gcm') === m ? 'selected' : ''}>${m}</option>`).join('')}</select></label>
            </div>
          </div>
          <div class="wiz-section"><h4><span class="step">4</span>${I18N.t('wizard_security')}</h4>
            <div class="grid-form">
              <label class="field"><span class="field-label" data-i18n="security"></span>
                <select class="select" name="security"><option value="tls" ${(u?.security || 'tls') === 'tls' ? 'selected' : ''}>TLS</option><option value="none" ${u?.security === 'none' ? 'selected' : ''}>None</option><option value="reality" ${u?.security === 'reality' ? 'selected' : ''}>Reality</option></select></label>
              <label class="field"><span class="field-label" data-i18n="fingerprint"></span>
                <select class="select" name="fingerprint">${FINGERPRINTS.map(fp => `<option value="${fp}" ${(u?.fingerprint || settings.default_fingerprint || 'chrome') === fp ? 'selected' : ''}>${fp}</option>`).join('')}</select></label>
              <label class="field"><span class="field-label" data-i18n="alpn"></span>
                <select class="select" name="alpn">${ALPNS.map(a => `<option value="${a}" ${(u?.alpn ?? settings.default_alpn ?? 'http/1.1') === a ? 'selected' : ''}>${a || '—'}</option>`).join('')}</select></label>
            </div>
          </div>
          <div class="wiz-section"><h4><span class="step">5</span>${I18N.t('wizard_limits')}</h4>
            <div class="grid-form">
              <label class="field"><span class="field-label" data-i18n="quota_gb"></span><input class="input" type="number" step="0.1" min="0" name="quota_gb" value="${u?.quota_gb || 0}"></label>
              <label class="field"><span class="field-label" data-i18n="expire_days"></span><input class="input" type="number" min="0" name="expire_days" value="${u?.expire_at ? Math.max(0, Math.ceil((u.expire_at - Date.now() / 1000) / 86400)) : 0}"></label>
              <label class="field"><span class="field-label" data-i18n="max_devices"></span><input class="input" type="number" min="0" name="max_devices" value="${u?.max_devices || 0}"></label>
              <label class="field"><span class="field-label" data-i18n="max_requests"></span><input class="input" type="number" min="0" name="max_requests" value="${u?.max_requests || 0}"></label>
              <label class="field full"><span class="field-label" data-i18n="allowed_ips"></span><input class="input" name="allowed_ips" value="${esc((u?.allowed_ips || []).join(','))}" dir="ltr"></label>
            </div>
          </div>
          <div class="wiz-section"><h4><span class="step">6</span>${I18N.t('wizard_preview')}</h4>
            <div id="cfgPreview"></div>
            <div class="cell-sub" style="margin-top:8px" data-i18n="preview_hint"></div>
          </div>
        </form>`,
      foot: `<button class="btn" data-close>${I18N.t('cancel')}</button>
             <button class="btn primary" id="saveCfgBtn">${I18N.t('save')}</button>`,
    });
    I18N.apply();
    wireAvatarPicker(m.query('#cfgForm'));
    wireProtoDeps(m.query('#cfgForm'));
    preview();
    m.query('#cfgForm').addEventListener('input', U.debounce(preview, 150));
    m.query('#saveCfgBtn').addEventListener('click', async () => {
      const body = collectUserForm(m.query('#cfgForm'));
      try {
        if (u) { await U.apiJson(`/api/users/${u.uid}`, { method: 'PATCH', body: JSON.stringify(body) }); }
        else {
          const res = await U.apiJson('/api/users', { method: 'POST', body: JSON.stringify(body) });
          U.closeModal();
          U.toast(I18N.t('config_created'), 'ok');
          await openLinksModal(res.user.uid);
          if (U.current === 'configs') U.render();
          return;
        }
        U.closeModal();
        U.toast('ok', 'ok');
        if (U.current === 'configs') U.render();
      } catch (err) { U.toast(err.message, 'err'); }
    });
  }

  // ================================================================ nodes
  async function nodesPage(view) {
    view.innerHTML = `
      <div class="page-head">
        <div><h1 class="page-title" data-i18n="nodes_title"></h1><p class="page-sub" data-i18n="nodes_sub"></p></div>
        <div class="page-actions">
          <button class="btn primary" id="autoNodeBtn">${ICONS.plus}<span data-i18n="node_add_auto"></span></button>
          <button class="btn" id="addNodeBtn">${ICONS.plus}<span data-i18n="add_node"></span></button>
        </div>
      </div>
      <div class="grid grid-3" id="nodesGrid">${U.skeleton(6)}</div>`;

    let nodes = [];
    async function load() {
      try { nodes = (await U.apiJson('/api/nodes')).nodes || []; }
      catch (e) { $('#nodesGrid').innerHTML = U.empty('⚠️', I18N.t('error'), e.message); return; }
      draw();
    }
    function metricBar(label, val) {
      const pct = Math.max(0, Math.min(100, Number(val) || 0));
      return `<div class="metric"><div class="m-lbl">${esc(label)}</div><div class="m-val">${val != null ? val + '%' : '—'}</div>
        <div class="m-bar"><i style="width:${val != null ? pct : 0}%"></i></div></div>`;
    }
    function draw() {
      $('#nodesGrid').innerHTML = nodes.length ? nodes.map(n => {
        const st = n.status || {};
        const sync = n.sync || {};
        const reason = !n.is_local && !st.online ? offlineReason(st) : '';
        const statusLine = !n.is_local ? `
          <div class="cell-sub" style="margin-bottom:10px">
            <span data-i18n="address"></span>: <span dir="ltr">${esc(n.address || '—')}</span>
            ${reason ? `<span style="color:var(--red)"> · ${reason}</span>` : ''}
          </div>` : '';
        const syncLine = !n.is_local ? `
          <div class="cell-sub" style="margin-bottom:10px">
            <span data-i18n="node_sync_users"></span>: <b>${sync.on_node != null ? sync.on_node : '—'}</b> / ${sync.expected != null ? sync.expected : '—'}
            ${!sync.has_credential ? `<span style="color:var(--red)"> · ${I18N.t('node_no_credential')}</span>` : ''}
            ${sync.on_node != null && sync.on_node < sync.expected ? `<span style="color:var(--gold)"> · ${I18N.t('node_sync_lag')}</span>` : ''}
          </div>` : '';
        return `<div class="node-card">
          <div class="n-head">
            <div class="n-flag">${flagHtml(n, 'flag-lg')}</div>
            <div class="grow">
              <div class="n-title">${esc(n.name)} ${n.is_local ? `<span class="tag">${I18N.t('local_node')}</span>` : ''}</div>
              <div class="n-sub">${esc([n.city !== '—' ? n.city : '', n.country !== '—' ? n.country : ''].filter(Boolean).join('، ') || '—')} · ${esc((n.country_code || '').toUpperCase())}</div>
            </div>
            ${nodeBadge(n)}
          </div>
          <div class="node-metrics">
            ${metricBar(I18N.t('cpu'), st.cpu)}
            ${metricBar(I18N.t('ram'), st.ram)}
            ${metricBar(I18N.t('disk'), st.disk)}
          </div>
          <div class="row" style="gap:8px;flex-wrap:wrap;margin-bottom:12px">
            <span class="cell-sub">${I18N.t('latency')}: <b>${st.latency_ms != null ? st.latency_ms + ' ms' : '—'}</b></span>
            <span class="cell-sub">${I18N.t('version')}: ${esc(n.version || '—')}</span>
            <span class="cell-sub">${I18N.t('last_seen')}: ${U.fmtDateTime(n.last_seen)}</span>
          </div>
          ${statusLine}
          ${syncLine}
          <div class="row" style="gap:8px;flex-wrap:wrap">
            <button class="btn sm" data-act="view" data-id="${n.id}">${ICONS.eye}<span data-i18n="node_view"></span></button>
            <button class="btn sm" data-act="ping" data-id="${n.id}">${ICONS.refresh}<span data-i18n="ping"></span></button>
            ${!n.is_local ? `<button class="btn sm" data-act="sync" data-id="${n.id}">${ICONS.refresh}<span data-i18n="node_sync_now"></span></button>` : ''}
            <button class="btn sm" data-act="edit" data-id="${n.id}">${ICONS.edit}<span data-i18n="edit"></span></button>
            <button class="btn sm" data-act="toggle" data-id="${n.id}">${ICONS.power}<span data-i18n="maintenance"></span></button>
            ${!n.is_local ? `<button class="btn sm danger" data-act="delete" data-id="${n.id}">${ICONS.trash}</button>` : ''}
          </div>
        </div>`;
      }).join('') : U.empty('🖥️', I18N.t('no_nodes'), I18N.t('no_nodes_sub'));
      I18N.apply();
    }
    $('#nodesGrid').addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-act]');
      if (!btn) return;
      const id = parseInt(btn.dataset.id, 10);
      const node = nodes.find(n => n.id === id);
      const act = btn.dataset.act;
      if (act === 'view') openNodeView(node);
      else if (act === 'ping') { btn.disabled = true; try { await U.apiJson(`/api/nodes/${id}/ping`, { method: 'POST' }); await load(); } finally { btn.disabled = false; } }
      else if (act === 'sync') {
        btn.disabled = true;
        try {
          const r = await U.apiJson(`/api/nodes/${id}/sync`, { method: 'POST' });
          U.toast(I18N.t('node_synced') + ' (' + r.pushed + ')', 'ok');
          await load();
        } catch (err) { U.toast(err.message, 'err'); }
        finally { btn.disabled = false; }
      }
      else if (act === 'edit') openNodeForm(node);
      else if (act === 'toggle') { await U.apiJson(`/api/nodes/${id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !node.enabled }) }); await load(); }
      else if (act === 'delete') {
        if (await U.confirmDlg(I18N.t('delete'), I18N.t('delete_confirm_node'))) { await U.apiJson(`/api/nodes/${id}`, { method: 'DELETE' }); await load(); }
      }
    });
    $('#addNodeBtn').addEventListener('click', () => openNodeForm(null));
    $('#autoNodeBtn').addEventListener('click', () => openNodeInvite());
    await load();
  }

  // Show the one-time credential for a manually-added node, so it can sync.
  function showNodeToken(token, name) {
    const origin = location.origin;
    const varsText = () => `TITAN_ROLE=node\nTITAN_MAIN_URL=${origin}\nTITAN_NODE_TOKEN=${token}`;
    const m = U.modal({
      title: I18N.t('node_token_title') + ' — ' + esc(name || ''),
      body: `
        <div class="cell-sub" style="margin-bottom:12px" data-i18n="node_token_hint"></div>
        <label class="field"><span class="field-label">TITAN_ROLE</span>
          <input class="input" value="node" readonly dir="ltr"></label>
        <label class="field"><span class="field-label">TITAN_MAIN_URL</span>
          <div class="row" style="gap:8px"><input class="input grow" value="${esc(origin)}" readonly dir="ltr"><button class="btn sm" id="cMain">${I18N.t('copy')}</button></div></label>
        <label class="field"><span class="field-label">TITAN_NODE_TOKEN</span>
          <div class="row" style="gap:8px"><input class="input grow" value="${esc(token)}" readonly dir="ltr"><button class="btn sm" id="cTok">${I18N.t('copy')}</button></div></label>
        <div class="row" style="gap:8px;margin-top:12px">
          <button class="btn" id="cAll">${I18N.t('node_copy_all')}</button>
        </div>`,
      foot: `<button class="btn" data-close>${I18N.t('close')}</button>`,
    });
    m.query('#cMain').addEventListener('click', () => { U.copyText(origin); U.toast(I18N.t('copied'), 'ok'); });
    m.query('#cTok').addEventListener('click', () => { U.copyText(token); U.toast(I18N.t('copied'), 'ok'); });
    m.query('#cAll').addEventListener('click', () => { U.copyText(varsText()); U.toast(I18N.t('copied'), 'ok'); });
    I18N.apply();
  }

  // Quick node setup: panel issues a token; the node self-registers with it.
  async function openNodeInvite() {
    let token = '';
    let nodeId = null;
    const origin = location.origin;
    const m = U.modal({
      title: I18N.t('node_auto_title'),
      lg: true,
      body: `
        <label class="field"><span class="field-label" data-i18n="name"></span>
          <input class="input" id="inviteName" data-i18n-ph="node_name_hint"></label>
        <div class="row" style="gap:8px;margin-top:10px">
          <button class="btn primary" id="inviteGen">${I18N.t('node_invite_gen')}</button>
        </div>
        <div id="inviteBody" class="hidden" style="margin-top:14px">
          <div class="cell-sub" data-i18n="node_invite_steps"></div>
          <ol style="margin:8px 0 14px;padding-inline-start:20px;line-height:1.7">
            <li data-i18n="node_step1"></li>
            <li data-i18n="node_step2"></li>
            <li data-i18n="node_step3"></li>
          </ol>
          <label class="field"><span class="field-label">TITAN_ROLE</span>
            <input class="input" value="node" readonly dir="ltr"></label>
          <label class="field"><span class="field-label">TITAN_MAIN_URL</span>
            <div class="row" style="gap:8px"><input class="input grow" id="inviteMainUrl" value="${esc(origin)}" readonly dir="ltr"><button class="btn sm" id="copyMain">${I18N.t('copy')}</button></div></label>
          <label class="field"><span class="field-label">TITAN_NODE_TOKEN</span>
            <div class="row" style="gap:8px"><input class="input grow" id="inviteToken" value="${esc(token)}" readonly dir="ltr"><button class="btn sm" id="copyToken">${I18N.t('copy')}</button></div></label>
          <div class="row" style="gap:8px;margin-top:12px">
            <button class="btn" id="copyAll">${I18N.t('node_copy_all')}</button>
            <button class="btn primary" id="inviteCheck">${I18N.t('node_check')}</button>
          </div>
          <div class="cell-sub mt" id="inviteStatus" style="margin-top:12px"></div>
        </div>`,
      foot: `<button class="btn" data-close>${I18N.t('close')}</button>`,
    });
    I18N.apply();

    const varsText = () => `TITAN_ROLE=node\nTITAN_MAIN_URL=${origin}\nTITAN_NODE_TOKEN=${token}`;
    m.query('#inviteGen').addEventListener('click', async () => {
      const name = m.query('#inviteName').value.trim() || 'Node';
      try {
        const r = await U.apiJson('/api/nodes/invite', { method: 'POST', body: JSON.stringify({ name }) });
        token = r.token;
        nodeId = r.node && r.node.id;
        m.query('#inviteToken').value = token;
        m.query('#inviteBody').classList.remove('hidden');
        I18N.apply();
      } catch (e) { U.toast(I18N.t('node_gen_fail'), 'err'); }
    });
    m.query('#copyMain').addEventListener('click', () => { U.copyText(origin); U.toast(I18N.t('copied'), 'ok'); });
    m.query('#copyToken').addEventListener('click', () => { U.copyText(token); U.toast(I18N.t('copied'), 'ok'); });
    m.query('#copyAll').addEventListener('click', () => { U.copyText(varsText()); U.toast(I18N.t('copied'), 'ok'); });
    m.query('#inviteCheck').addEventListener('click', async () => {
      const st = m.query('#inviteStatus');
      try {
        const nodes = (await U.apiJson('/api/nodes')).nodes || [];
        const n = nodes.find(x => x.id === nodeId);
        if (n && n.address) {
          st.innerHTML = `${I18N.t('node_registered')} — ${flagHtml(n, 'flag-sm')} ${esc(n.country || n.address)}`;
          if (U.current === 'nodes') U.render();
        } else {
          st.textContent = I18N.t('node_waiting');
        }
      } catch (e) { st.textContent = e.message; }
    });
  }

  function openNodeView(node) {
    const st = node.status || {};
    U.modal({
      title: esc(node.name),
      body: `
        <div class="row" style="gap:12px;margin-bottom:14px">
          <div>${flagHtml(node, 'flag-lg')}</div>
          <div>
            <div style="font-weight:800">${esc(node.name)}</div>
            <div class="cell-sub">${esc([node.city !== '—' ? node.city : '', node.country !== '—' ? node.country : ''].filter(Boolean).join('، ') || '—')}</div>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:.84rem">
          <div><span class="cell-sub">${I18N.t('status')}:</span> ${nodeBadge(node)}</div>
          <div><span class="cell-sub">${I18N.t('latency')}:</span> ${st.latency_ms != null ? st.latency_ms + ' ms' : '—'}</div>
          <div><span class="cell-sub">${I18N.t('address')}:</span> <span dir="ltr">${esc(node.address || '—')}</span></div>
          <div><span class="cell-sub">${I18N.t('version')}:</span> ${esc(node.version || '—')}</div>
          <div><span class="cell-sub">${I18N.t('last_seen')}:</span> ${U.fmtDateTime(node.last_seen)}</div>
          ${!node.is_local && !st.online ? `<div style="grid-column:1/-1"><span class="cell-sub">${I18N.t('reason')}:</span> <span style="color:var(--red)">${offlineReason(st)}</span></div>` : ''}
        </div>`,
      foot: `<button class="btn" data-close>${I18N.t('close')}</button>`,
    });
    I18N.apply();
  }

  function openNodeForm(node) {
    const cc = node?.country_code || '';
    const flagInputId = 'nodeFlag';
    const m = U.modal({
      title: I18N.t(node ? 'edit' : 'add_node'),
      body: `
        <form id="nodeForm">
          <label class="field"><span class="field-label" data-i18n="name"></span><input class="input" name="name" value="${esc(node?.name || '')}" required></label>
          <label class="field"><span class="field-label" data-i18n="address"></span><input class="input" name="address" value="${esc(node?.address || '')}" dir="ltr" placeholder="https://example.com"></label>
          <div class="grid-form">
            <label class="field"><span class="field-label" data-i18n="city"></span><input class="input" name="city" value="${esc(node?.city || '')}"></label>
            <label class="field"><span class="field-label" data-i18n="country"></span><input class="input" name="country" value="${esc(node?.country || '')}"></label>
            <label class="field"><span class="field-label" data-i18n="country_code"></span><input class="input" name="country_code" id="nodeCc" value="${esc(cc)}" maxlength="2" style="text-transform:uppercase"></label>
            <label class="field"><span class="field-label" data-i18n="flag_placeholder"></span><input class="input" name="flag" id="${flagInputId}" value="${esc(node?.flag || flagFor(cc))}"></label>
          </div>
        </form>`,
      foot: `<button class="btn" data-close>${I18N.t('cancel')}</button>
             <button class="btn primary" id="saveNodeBtn">${I18N.t('save')}</button>`,
    });
    I18N.apply();
    m.query('#nodeCc').addEventListener('input', () => {
      m.query('#' + flagInputId).value = flagFor(m.query('#nodeCc').value);
    });
    m.query('#saveNodeBtn').addEventListener('click', async () => {
      const fd = new FormData(m.query('#nodeForm'));
      const body = {
        name: fd.get('name'), address: fd.get('address'), city: fd.get('city'),
        country: fd.get('country'), country_code: fd.get('country_code'), flag: fd.get('flag'),
      };
      try {
        if (node) {
          await U.apiJson(`/api/nodes/${node.id}`, { method: 'PATCH', body: JSON.stringify(body) });
          U.closeModal();
          U.toast(I18N.t('node_updated'), 'ok');
        } else {
          const res = await U.apiJson('/api/nodes', { method: 'POST', body: JSON.stringify(body) });
          U.closeModal();
          U.toast(I18N.t('node_created'), 'ok');
          if (res.token) showNodeToken(res.token, body.name);
        }
        if (U.current === 'nodes') U.render();
      } catch (err) { U.toast(err.message, 'err'); }
    });
  }

  // ================================================================ subscriptions
  async function subscriptions(view) {
    view.innerHTML = `
      <div class="page-head">
        <div><h1 class="page-title" data-i18n="subs_title"></h1><p class="page-sub" data-i18n="subs_sub"></p></div>
      </div>
      <div class="table-wrap">
        <table class="data">
          <thead><tr>
            <th data-i18n="user"></th><th data-i18n="sub_status"></th><th data-i18n="expiry"></th>
            <th class="num" data-i18n="traffic_used"></th><th class="num" data-i18n="config_count"></th><th data-i18n="actions"></th>
          </tr></thead>
          <tbody id="subRows"><tr><td colspan="6">${U.skeleton(8)}</td></tr></tbody>
        </table>
      </div>`;
    let users = [];
    async function load() {
      try { users = (await U.apiJson('/api/users')).users || []; }
      catch (e) { $('#subRows').innerHTML = `<tr><td colspan="6">${U.empty('⚠️', I18N.t('error'), e.message)}</td></tr>`; return; }
      $('#subRows').innerHTML = users.length ? users.map(u => {
        const st = u.status || {};
        const state = st.expired ? badge(I18N.t('expired'), 'warn') : (!u.enabled ? badge(I18N.t('inactive'), 'bad') : badge(I18N.t('enabled'), 'ok'));
        return `<tr>
          <td><div class="cell-main"><div class="u-inline">${userAvatarHtml(u)}<span class="cell-title">${esc(u.name)}</span></div><span class="cell-sub">${protoTag(u.protocol)}</span></div></td>
          <td>${state}</td>
          <td>${u.expire_at ? U.fmtDate(u.expire_at) : `<span class="cell-sub">${I18N.t('never')}</span>`}</td>
          <td class="num">${U.fmtBytes(st.used || 0)}</td>
          <td class="num">1</td>
          <td>
            <div class="row-actions">
              <button class="icon-btn" data-act="copy" data-uid="${u.uid}" title="${I18N.t('copy_sub')}">${ICONS.copy}</button>
              <button class="icon-btn" data-act="qr" data-uid="${u.uid}" title="${I18N.t('qr')}">${ICONS.qr}</button>
              <button class="icon-btn" data-act="view" data-uid="${u.uid}" title="${I18N.t('view')}">${ICONS.eye}</button>
              <button class="icon-btn" data-act="revoke" data-uid="${u.uid}" title="${I18N.t('revoke')}">${ICONS.refresh}</button>
            </div>
          </td>
        </tr>`;
      }).join('') : `<tr><td colspan="6">${U.empty('🔗', I18N.t('no_subs'), '')}</td></tr>`;
      I18N.apply();
    }
    $('#subRows').addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-act]');
      if (!btn) return;
      const uid = btn.dataset.uid, act = btn.dataset.act;
      if (act === 'copy') {
        const d = await U.apiJson(`/api/users/${uid}/links`);
        U.copyText(d.sub_url);
      } else if (act === 'view') await openLinksModal(uid);
      else if (act === 'qr') {
        U.modal({ title: I18N.t('qr'), body: `<div style="text-align:center"><img src="/api/users/${uid}/qr" style="max-width:100%;border-radius:12px" alt="QR"></div>`, foot: `<button class="btn" data-close>${I18N.t('close')}</button>` });
      } else if (act === 'revoke') {
        if (await U.confirmDlg(I18N.t('revoke'), I18N.t('rotate_confirm'))) {
          await U.apiJson(`/api/users/${uid}/regenerate`, { method: 'POST' });
          U.toast('ok', 'ok');
        }
      }
    });
    await load();
  }

  // ================================================================ reports
  async function reports(view) {
    view.innerHTML = `
      <div class="page-head">
        <div><h1 class="page-title" data-i18n="reports_title"></h1><p class="page-sub" data-i18n="reports_sub"></p></div>
        <div class="page-actions" id="rangeSeg"></div>
      </div>
      <div class="stat-grid" id="repStats"></div>
      <div class="grid grid-23 mt">
        <div class="panel">
          <div class="panel-head">
            <div><div class="panel-title" data-i18n="chart_traffic"></div><div class="panel-sub" id="repChartSub"></div></div>
          </div>
          <div class="panel-body"><div class="chart-wrap" id="repChart">${U.skeleton(6)}</div></div>
        </div>
        <div class="panel">
          <div class="panel-head"><div><div class="panel-title" data-i18n="rep_protocol_dist"></div><div class="panel-sub"></div></div></div>
          <div class="panel-body" id="protoDist">${U.skeleton(5)}</div>
        </div>
      </div>
      <div class="panel mt">
        <div class="panel-head"><div><div class="panel-title" data-i18n="rep_top_users"></div><div class="panel-sub"></div></div></div>
        <div class="panel-body" id="topUsers">${U.skeleton(5)}</div>
      </div>`;

    let days = 7;
    const segs = [
      { d: 7, label: 'rep_days_7' }, { d: 14, label: 'rep_days_14' }, { d: 30, label: 'rep_days_30' },
    ];
    $('#rangeSeg').innerHTML = segs.map(s =>
      `<button class="btn ${s.d === days ? 'primary' : ''}" data-days="${s.d}" data-i18n="${s.label}"></button>`).join('');
    $('#rangeSeg').addEventListener('click', async (e) => {
      const b = e.target.closest('[data-days]');
      if (!b) return;
      days = parseInt(b.dataset.days, 10);
      $$('#rangeSeg .btn').forEach(x => x.classList.remove('primary'));
      b.classList.add('primary');
      await load();
    });

    async function load() {
      let r = null;
      try { r = await U.apiJson(`/api/reports?days=${days}`); }
      catch (e) { view.innerHTML = U.empty('⚠️', I18N.t('error'), e.message); return; }
      const t = r.totals || {};
      const totalTraffic = (t.total_up || 0) + (t.total_down || 0);
      $('#repStats').innerHTML = [
        { l: 'rep_total_traffic', v: U.fmtBytes(totalTraffic) },
        { l: 'rep_users', v: t.users },
        { l: 'rep_active', v: t.active },
        { l: 'rep_expired', v: t.expired },
        { l: 'rep_disabled', v: t.disabled },
      ].map(c => `<div class="stat-card"><span class="glow"></span><div class="stat-top"><span class="stat-label" data-i18n="${c.l}"></span></div><div class="stat-value">${esc(String(c.v))}</div></div>`).join('');

      const daily = r.daily || [];
      $('#repChartSub').textContent = I18N.t('rep_days_' + days);
      if (daily.some(d => d.up || d.down)) U.drawChart('#repChart', daily, { daily: true });
      else $('#repChart').innerHTML = U.empty('📊', I18N.t('empty_traffic'), '');

      // protocol distribution
      const prots = r.protocols || [];
      const totalProts = prots.reduce((a, p) => a + p.count, 0) || 1;
      $('#protoDist').innerHTML = prots.length ? prots.map(p => `
        <div style="margin-bottom:14px">
          <div class="row" style="justify-content:space-between;margin-bottom:5px">
            <span style="font-weight:700">${esc(p.protocol.toUpperCase())}</span>
            <span class="cell-sub">${p.count} (${Math.round((p.count / totalProts) * 100)}%)</span>
          </div>
          <div class="progress"><i style="width:${(p.count / totalProts) * 100}%"></i></div>
        </div>`).join('') : U.empty('📊', I18N.t('no_data'), '');

      $('#topUsers').innerHTML = (r.top_users || []).length ? `
        <table class="data" style="box-shadow:none;border:none;background:transparent">
          <thead><tr><th data-i18n="user"></th><th class="num" data-i18n="rep_traffic"></th></tr></thead>
          <tbody>${r.top_users.map(u => `<tr><td><span class="cell-title">${esc(u.name)}</span></td><td class="num">${U.fmtBytes(u.used)}</td></tr>`).join('')}</tbody>
        </table>` : U.empty('👤', I18N.t('no_users'), '');
      I18N.apply();
    }
    await load();
  }

  // ================================================================ settings
  async function settingsPage(view) {
    let s = null;
    try { s = await U.apiJson('/api/settings'); } catch (e) { view.innerHTML = U.empty('⚠️', I18N.t('error'), e.message); return; }
    let defaultAuth = false;
    try { defaultAuth = (await U.apiJson('/api/me')).default_auth; } catch (_) { /* noop */ }
    const sw = (key, label) => `
      <div class="row" style="justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)">
        <span data-i18n="${label}"></span>
        <label class="switch"><input type="checkbox" data-key="${key}" ${s[key] ? 'checked' : ''}><span class="track"></span></label>
      </div>`;
    view.innerHTML = `
      <div class="page-head">
        <div><h1 class="page-title" data-i18n="settings_title"></h1><p class="page-sub" data-i18n="settings_sub"></p></div>
        <div class="page-actions"><button class="btn primary" id="saveSettings">${ICONS.check}<span data-i18n="save"></span></button></div>
      </div>
      <div class="grid grid-2">
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="sec_general"></div></div>
          <div class="panel-body">
            <label class="field"><span class="field-label" data-i18n="set_lang"></span>
              <select class="select" data-key="lang"><option value="fa" ${s.lang === 'fa' ? 'selected' : ''}>فارسی</option><option value="en" ${s.lang === 'en' ? 'selected' : ''}>English</option></select></label>
            <label class="field"><span class="field-label" data-i18n="set_theme"></span>
              <select class="select" data-key="theme"><option value="dark" ${s.theme === 'dark' ? 'selected' : ''} data-i18n="theme_dark"></option><option value="light" ${s.theme === 'light' ? 'selected' : ''} data-i18n="theme_light"></option></select></label>
            <label class="field"><span class="field-label" data-i18n="set_public_domain"></span>
              <input class="input" data-key="public_domain" value="${esc(s.public_domain)}" dir="ltr"></label>
            <label class="field"><span class="field-label" data-i18n="set_public_port"></span>
              <input class="input" type="number" min="1" max="65535" data-key="public_port" value="${esc(s.public_port || 443)}" dir="ltr"></label>
            <div class="cell-sub" style="margin-top:2px" data-i18n="public_access_hint"></div>
          </div>
        </div>
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="sec_security"></div></div>
          <div class="panel-body">
            ${defaultAuth ? `<div class="badge warn" style="margin-bottom:14px"><span class="dot"></span><span data-i18n="default_auth_warn"></span></div>` : ''}
            <label class="field"><span class="field-label" data-i18n="set_old_password"></span><input class="input" type="password" id="oldPass" autocomplete="current-password" ${defaultAuth ? 'placeholder="—"' : ''}></label>
            <label class="field"><span class="field-label" data-i18n="set_new_password"></span><input class="input" type="password" id="newPass" autocomplete="new-password"></label>
            <button class="btn" id="changePassBtn">${ICONS.key}<span data-i18n="set_change_password"></span></button>
          </div>
        </div>
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="sec_network"></div></div>
          <div class="panel-body">
            <label class="field"><span class="field-label" data-i18n="set_transport"></span>
              <select class="select" data-key="default_transport">${TRANSPORTS.map(t => `<option value="${t}" ${s.default_transport === t ? 'selected' : ''}>${t.toUpperCase()}</option>`).join('')}</select></label>
            <label class="field"><span class="field-label" data-i18n="set_fingerprint"></span>
              <select class="select" data-key="default_fingerprint">${FINGERPRINTS.map(fp => `<option value="${fp}" ${s.default_fingerprint === fp ? 'selected' : ''}>${fp}</option>`).join('')}</select></label>
            <label class="field"><span class="field-label" data-i18n="set_alpn"></span>
              <select class="select" data-key="default_alpn">${ALPNS.map(a => `<option value="${a}" ${s.default_alpn === a ? 'selected' : ''}>${a || '—'}</option>`).join('')}</select></label>
            <label class="field"><span class="field-label" data-i18n="set_sni"></span>
              <input class="input" data-key="sni_override" value="${esc(s.sni_override)}" dir="ltr"></label>
          </div>
        </div>
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="sec_avatar"></div></div>
          <div class="panel-body">
            <div class="row" style="gap:16px;flex-wrap:wrap;align-items:center;margin-bottom:14px">
              <img class="avatar-preview" id="avatarPreview" src="/static/img/titan-avatar.svg" alt="avatar">
              <div class="cell-sub" data-i18n="avatar_hint"></div>
            </div>
            <div class="row" style="gap:8px;flex-wrap:wrap">
              <button class="btn primary" id="avatarChangeBtn">${ICONS.link}<span data-i18n="gallery_choose"></span></button>
            </div>
          </div>
        </div>
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="sec_system"></div></div>
          <div class="panel-body">
            ${sw('restrict_ips', 'set_restrict_ips')}
            ${sw('block_ads', 'set_block_ads')}
            ${sw('block_iran_sites', 'set_block_iran')}
            ${sw('notify_new_conn', 'set_notify_conn')}
            ${sw('fragment_enabled', 'set_fragment')}
            <div class="grid-form mt" style="gap:0 14px">
              <label class="field"><span class="field-label" data-i18n="set_fragment_packets"></span><input class="input" data-key="fragment_packets" value="${esc(s.fragment_packets)}"></label>
              <label class="field"><span class="field-label" data-i18n="set_fragment_length"></span><input class="input" data-key="fragment_length" value="${esc(s.fragment_length)}"></label>
              <label class="field"><span class="field-label" data-i18n="set_fragment_interval"></span><input class="input" data-key="fragment_interval" value="${esc(s.fragment_interval)}"></label>
            </div>
            <button class="btn danger mt" id="restartBtn">${ICONS.power}<span data-i18n="set_restart"></span></button>
          </div>
        </div>
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="sec_backup"></div></div>
          <div class="panel-body">
            ${sw('backup_enabled', 'set_backup_auto')}
            <label class="field mt"><span class="field-label" data-i18n="set_backup_interval"></span><input class="input" type="number" min="1" data-key="backup_interval_hours" value="${s.backup_interval_hours}"></label>
            <div class="row" style="gap:8px;flex-wrap:wrap">
              <button class="btn" id="backupBtn">${ICONS.download}<span data-i18n="set_backup_download"></span></button>
              <button class="btn" id="restoreBtn">${ICONS.upload}<span data-i18n="set_backup_restore"></span></button>
              <input type="file" id="restoreFile" accept=".b64,.gz,application/octet-stream" class="hidden">
            </div>
          </div>
        </div>
      </div>`;
    I18N.apply();

    $('#saveSettings').addEventListener('click', async () => {
      const body = {};
      $$('[data-key]', view).forEach(el => { body[el.dataset.key] = el.type === 'checkbox' ? el.checked : el.value; });
      try {
        await U.apiJson('/api/settings', { method: 'POST', body: JSON.stringify(body) });
        U.toast(I18N.t('settings_saved'), 'ok');
      } catch (e) { U.toast(e.message, 'err'); }
    });
    $('#changePassBtn').addEventListener('click', async () => {
      try {
        await U.apiJson('/api/change-password', { method: 'POST', body: JSON.stringify({ old_password: $('#oldPass').value, new_password: $('#newPass').value }) });
        U.toast(I18N.t('password_changed'), 'ok');
        $('#oldPass').value = ''; $('#newPass').value = '';
      } catch (e) { U.toast(I18N.t(e.message === 'wrong-old-password' ? 'wrong_old_password' : 'error'), 'err'); }
    });

    // --- admin profile picture (avatar gallery) ---
    const renderAvatar = () => {
      const prev = $('#avatarPreview');
      if (prev) prev.src = avatarUrl(s.admin_avatar);
    };
    renderAvatar();
    $('#avatarChangeBtn').addEventListener('click', async () => {
      const key = await openGalleryPicker({ current: s.admin_avatar === 'titan' ? '' : s.admin_avatar });
      if (key == null) return;
      try {
        await U.apiJson('/api/admin-avatar', { method: 'POST', body: JSON.stringify({ avatar: key }) });
        s.admin_avatar = key || 'titan';
        renderAvatar();
        syncTopbarAvatar(key);
        U.toast(I18N.t('avatar_saved'), 'ok');
      } catch (err) { U.toast(err.message, 'err'); }
    });
    $('#backupBtn').addEventListener('click', () => { location.href = '/api/backup'; });
    $('#restoreBtn').addEventListener('click', () => $('#restoreFile').click());
    $('#restoreFile').addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (!(await U.confirmDlg(I18N.t('set_backup_restore'), I18N.t('restore_confirm')))) return;
      const fd = new FormData(); fd.append('file', file);
      try {
        const r = await fetch('/api/backup/restore', { method: 'POST', body: fd });
        const d = await r.json().catch(() => ({}));
        if (r.ok) U.toast('ok', 'ok'); else U.toast(d.detail || 'err', 'err');
      } catch (_) { U.toast('err', 'err'); }
    });
    $('#restartBtn').addEventListener('click', async () => {
      if (await U.confirmDlg(I18N.t('set_restart'), I18N.t('restart_confirm'))) {
        await U.apiJson('/api/restart', { method: 'POST' });
        U.toast('restarting…');
      }
    });
  }

  // ================================================================ admins
  async function admins(view) {
    view.innerHTML = `
      <div class="page-head">
        <div><h1 class="page-title" data-i18n="admins_title"></h1><p class="page-sub" data-i18n="admins_sub"></p></div>
      </div>
      <div class="grid grid-2">
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="account_info"></div></div>
          <div class="panel-body" id="adminCard">${U.skeleton(3)}</div>
        </div>
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="audit_log"></div>
          <div class="page-actions">
            <select class="select" id="logLevel" style="width:auto;height:34px"><option value="">${I18N.t('all')}</option><option value="info">info</option><option value="warn">warn</option><option value="error">error</option></select>
            <button class="btn sm danger" id="clearLogs">${ICONS.trash}<span data-i18n="clear_logs"></span></button>
          </div>
        </div>
          <div class="panel-body" id="auditBox">${U.skeleton(6)}</div>
        </div>
      </div>`;

    try {
      const [info] = await Promise.all([U.apiJson('/api/admin-info')]);
      const adminAv = (info.avatar && info.avatar.url) || '/static/img/titan-avatar.svg';
      $('#adminCard').innerHTML = `
        <div class="profile-card">
          <div class="avatar"><img src="${esc(adminAv)}" alt="avatar" style="width:100%;height:100%;object-fit:cover"></div>
          <div class="grow">
            <div style="font-weight:800;font-size:1.1rem">${esc(info.username || I18N.t('admin'))}</div>
            <div class="cell-sub">${badge(info.role || I18N.t('role_super'), 'ok')}</div>
          </div>
          <button class="btn sm" id="adminAvatarBtn">${ICONS.link}<span data-i18n="change_picture"></span></button>
        </div>
        <div class="profile-stats mt">
          <div class="metric"><div class="m-lbl" data-i18n="created_at"></div><div class="m-val">${U.fmtDate(info.created_at)}</div></div>
          <div class="metric"><div class="m-lbl" data-i18n="last_login"></div><div class="m-val">${U.fmtDateTime(info.last_login)}</div></div>
          <div class="metric"><div class="m-lbl" data-i18n="ip"></div><div class="m-val" dir="ltr">${esc(info.last_login_ip || '—')}</div></div>
        </div>`;
    } catch (e) { $('#adminCard').innerHTML = U.empty('⚠️', I18N.t('error'), e.message); }

    const abtn = $('#adminAvatarBtn');
    if (abtn) abtn.addEventListener('click', async () => {
      const info = await U.apiJson('/api/admin-info').catch(() => null);
      const cur = (info && info.avatar && info.avatar.key) === 'titan' ? '' : ((info && info.avatar && info.avatar.key) || '');
      const key = await openGalleryPicker({ current: cur });
      if (key == null) return;
      try {
        await U.apiJson('/api/admin-avatar', { method: 'POST', body: JSON.stringify({ avatar: key }) });
        U.toast(I18N.t('avatar_saved'), 'ok');
        const img = $('#adminCard .profile-card .avatar img');
        if (img) img.src = avatarUrl(key);
        syncTopbarAvatar(key);
      } catch (err) { U.toast(err.message, 'err'); }
    });

    const loadLogs = async () => {
      const lvl = $('#logLevel').value;
      try {
        const d = await U.apiJson('/api/events?limit=200' + (lvl ? '&level=' + lvl : ''));
        const rows = d.events || [];
        $('#auditBox').innerHTML = rows.length ? `
          <table class="data" style="box-shadow:none;border:none;background:transparent">
            <thead><tr><th data-i18n="date"></th><th data-i18n="level"></th><th data-i18n="event"></th><th data-i18n="ip"></th></tr></thead>
            <tbody>${rows.map(e => `<tr>
              <td class="cell-sub">${U.fmtDateTime(e.ts)}</td>
              <td>${badge(e.level, e.level === 'warn' ? 'warn' : e.level === 'error' ? 'bad' : 'ok')}</td>
              <td>${esc(e.action)} <span class="cell-sub">${esc(e.detail || '')}</span></td>
              <td class="cell-sub" dir="ltr">${esc(e.ip || '—')}</td>
            </tr>`).join('')}</tbody>
          </table>` : U.empty('📜', I18N.t('no_data'), '');
        I18N.apply();
      } catch (e) { $('#auditBox').innerHTML = U.empty('⚠️', I18N.t('error'), e.message); }
    };
    $('#logLevel').addEventListener('change', loadLogs);
    $('#clearLogs').addEventListener('click', async () => {
      await U.apiJson('/api/events', { method: 'DELETE' });
      loadLogs();
    });
    await loadLogs();
    I18N.apply();
  }

  // ================================================================ tools
  async function tools(view) {
    view.innerHTML = `
      <div class="page-head">
        <div><h1 class="page-title" data-i18n="tools_title"></h1><p class="page-sub" data-i18n="tools_sub"></p></div>
      </div>
      <div class="grid grid-2">
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="diag"></div></div>
          <div class="panel-body" id="diagBox">${U.skeleton(4)}</div>
        </div>
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="health"></div></div>
          <div class="panel-body" id="healthBox">${U.skeleton(4)}</div>
        </div>
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="conn_diag"></div></div>
          <div class="panel-body" id="connBox">${U.skeleton(4)}</div>
        </div>
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="conn_test"></div>
          <div class="page-actions"><button class="btn sm primary" id="connTestBtn">${ICONS.refresh}<span data-i18n="conn_test_run"></span></button></div></div>
          <div class="panel-body" id="connTestBox"><div class="cell-sub" data-i18n="conn_untested"></div></div>
        </div>
        <div class="panel"><div class="panel-head"><div class="panel-title" data-i18n="sec_backup"></div></div>
          <div class="panel-body">
            <div class="row" style="gap:8px;flex-wrap:wrap">
              <button class="btn" id="bkBtn">${ICONS.download}<span data-i18n="set_backup_download"></span></button>
              <button class="btn" id="rsBtn">${ICONS.upload}<span data-i18n="set_backup_restore"></span></button>
              <input type="file" id="rsFile" accept=".b64,.gz,application/octet-stream" class="hidden">
              <button class="btn danger" id="rtBtn">${ICONS.power}<span data-i18n="set_restart"></span></button>
            </div>
          </div>
        </div>
      </div>`;

    try {
      const stats = await U.apiJson('/api/stats');
      $('#diagBox').innerHTML = `
        <div class="node-metrics">
          ${[['cpu', stats.cpu_percent + '%'], ['ram', stats.mem_percent + '%'], ['disk', stats.disk_percent + '%']].map(m =>
            `<div class="metric"><div class="m-lbl">${I18N.t(m[0])}</div><div class="m-val">${m[1]}</div><div class="m-bar"><i style="width:${Math.min(100, parseFloat(m[1]))}%"></i></div></div>`).join('')}
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px;font-size:.84rem">
          <div><span class="cell-sub">${I18N.t('uptime')}:</span> ${U.fmtUptime(stats.uptime_seconds)}</div>
          <div><span class="cell-sub">${I18N.t('app_version')}:</span> ${esc(stats.app_version)}</div>
          <div><span class="cell-sub">${I18N.t('xray_status')}:</span> ${stats.xray_running ? badge(I18N.t('running'), 'ok') : badge(I18N.t('not_running'), 'bad')}</div>
          <div><span class="cell-sub">${I18N.t('nav_nodes')}:</span> ${stats.nodes_count}</div>
        </div>`;
    } catch (e) { $('#diagBox').innerHTML = U.empty('⚠️', I18N.t('error'), e.message); }

    try {
      const stats2 = await U.apiJson('/api/stats');
      const loc = stats2.location || {};
      $('#healthBox').innerHTML = `
        <div class="row" style="gap:12px;padding:6px 0">
          <span class="stat-icon" style="width:46px;height:46px">${ICONS.globe}</span>
          <div>
            <div style="font-weight:800">${esc(loc.city || '—')}</div>
            <div class="cell-sub">${esc((loc.country || ''))} · ${esc(loc.colo || '')}</div>
          </div>
          ${stats2.xray_running ? badge(I18N.t('running'), 'ok') : badge(I18N.t('not_running'), 'bad')}
        </div>
        <div class="cell-sub mt" style="padding:6px 0">${I18N.t('total')}: ${U.fmtBytes((stats2.total_up || 0) + (stats2.total_down || 0))}</div>`;
    } catch (_) { /* noop */ }

    try {
      const nodes = (await U.apiJson('/api/nodes')).nodes || [];
      $('#connBox').innerHTML = nodes.length ? nodes.map(n => `
        <div class="node-row">
          <div class="node-flag">${flagHtml(n, 'flag-lg')}</div>
          <div class="node-meta"><div class="node-name">${esc(n.name)}</div><div class="node-city">${esc(n.city !== '—' ? n.city : n.country)}</div></div>
          ${nodeBadge(n)}
          <span class="node-latency">${n.status && n.status.latency_ms != null ? n.status.latency_ms + ' ms' : '—'}</span>
        </div>`).join('') : U.empty('🖥️', I18N.t('no_nodes'), '');
      I18N.apply();
    } catch (_) { /* noop */ }

    const statusLine = (ok) => `<span style="color:${ok ? 'var(--green)' : 'var(--red)'}">${ok ? I18N.t('conn_ok') : I18N.t('conn_fail')}</span>`;
    const renderConnTest = (r) => {
      const row = (label, v) => `<div class="row" style="justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border)"><span class="cell-sub">${label}</span><span>${v}</span></div>`;
      const pub = r.public || {};
      let pubHTML = '';
      if (r.domain) {
        if (pub.error) pubHTML = row(I18N.t('conn_domain') + ' (' + r.domain + ')', statusLine(false) + `<div class="cell-sub" dir="ltr">${esc(pub.error)}</div>`);
        else pubHTML =
          row(I18N.t('conn_panel_http'), esc(pub.panel_http_status != null ? pub.panel_http_status : '—')) +
          row(I18N.t('conn_ws_path'), pub.ws_path_routed ? statusLine(true) : statusLine(false) + ` (${esc(pub.ws_status != null ? pub.ws_status : '—')})`);
      } else {
        pubHTML = row(I18N.t('conn_domain'), I18N.t('conn_not_configured'));
      }
      $('#connTestBox').innerHTML =
        row(I18N.t('conn_xray'), r.xray_installed ? (r.xray_running ? statusLine(true) : statusLine(false) + ' (installed, not running)') : statusLine(false) + ' (not installed)') +
        row(I18N.t('conn_config'), r.config_valid == null ? I18N.t('conn_untested') : (r.config_valid ? statusLine(true) : statusLine(false))) +
        pubHTML;
      I18N.apply();
    };
    $('#connTestBtn').addEventListener('click', async () => {
      const b = $('#connTestBtn');
      b.disabled = true;
      $('#connTestBox').innerHTML = `<div class="cell-sub">${I18N.t('conn_testing')}</div>`;
      try {
        const r = await U.apiJson('/api/connection-test');
        renderConnTest(r);
      } catch (e) {
        $('#connTestBox').innerHTML = `<div class="cell-sub" style="color:var(--red)">${esc(e.message)}</div>`;
      } finally { b.disabled = false; }
    });

    $('#bkBtn').addEventListener('click', () => { location.href = '/api/backup'; });
    $('#rsBtn').addEventListener('click', () => $('#rsFile').click());
    $('#rsFile').addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (!(await U.confirmDlg(I18N.t('set_backup_restore'), I18N.t('restore_confirm')))) return;
      const fd = new FormData(); fd.append('file', file);
      try {
        const r = await fetch('/api/backup/restore', { method: 'POST', body: fd });
        if (r.ok) U.toast('ok', 'ok');
      } catch (_) { U.toast('err', 'err'); }
    });
    $('#rtBtn').addEventListener('click', async () => {
      if (await U.confirmDlg(I18N.t('set_restart'), I18N.t('restart_confirm'))) {
        await U.apiJson('/api/restart', { method: 'POST' });
        U.toast('restarting…');
      }
    });
    I18N.apply();
  }

  // expose avatar helpers for the dashboard shell
  U.openAvatarPicker = openGalleryPicker;
  U.avatarUrl = avatarUrl;

  // register pages
  U.setPages({ dashboard, users, configs, nodes: nodesPage, subscriptions, reports, settings: settingsPage, admins, tools });
})();
