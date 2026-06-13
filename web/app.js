// ── state ──────────────────────────────────────────────────────────────────
let CFG = null;
function _setCFG(cfg) {
  CFG = cfg;
  if (cfg?.own_display_name || cfg?.own_handle) {
    if (!serverProfiles[cfg.own_server]?.display_name) {
      serverProfiles[cfg.own_server] = { display_name: cfg.own_display_name, handle: cfg.own_handle };
    }
  }
  _refreshInviteBtn();
}

async function _refreshInviteBtn() {
  const btn = document.getElementById('invite-friend-btn');
  if (!btn) return;
  const { provider_url, own_identity } = CFG || {};
  if (!provider_url || !own_identity) { btn.hidden = true; return; }
  try {
    const r = await fetch(`${provider_url}/nodes/invite-status?identity=${encodeURIComponent(own_identity)}`);
    if (r.ok && (await r.json()).eligible) {
      btn.href = provider_url + '/invite/friend';
      btn.hidden = false;
      return;
    }
  } catch { /* provider unreachable */ }
  btn.hidden = true;
}
let activeServer = null;
let activeTags = new Set();
let allPosts = [];
let currentIdx = -1; // used by openEdit only
let nextCursor = null, currentSearch = null, searchTimer = null;
let pendingFiles = [];  // no longer used for upload — kept for compat
let _uploadedAssets = []; // {id, title, media_type, markup}
const DRAFT_KEY = 'contacc_compose_draft';

function _saveDraft() {
  const body = document.getElementById("compose-body")?.value || "";
  if (!body.trim()) { localStorage.removeItem(DRAFT_KEY); return; }
  localStorage.setItem(DRAFT_KEY, JSON.stringify({
    body,
    tags: document.getElementById("compose-tags")?.value || "",
    visibility: document.getElementById("compose-visibility")?.value || "contacts",
  }));
}

function _clearDraft() { localStorage.removeItem(DRAFT_KEY); }
let IS_OWNER = false;
let serverStatuses = {};
let serverOnline = {};  // server_url → boolean, from server_status in feed response
let serverHandles = {};
let serverProfiles = {};
function _profileCacheKey() { return 'profilesv1:' + (CFG?.own_server || ''); }
function _saveProfileCache() {
  try { localStorage.setItem(_profileCacheKey(), JSON.stringify(serverProfiles)); } catch(e) {}
}
function _loadProfileCache() {
  try {
    const d = JSON.parse(localStorage.getItem(_profileCacheKey()) || 'null');
    if (d) Object.assign(serverProfiles, d);
  } catch(e) {}
}
let serverPublicKeys = {}; // base64 pubkey → server url
let _keyToProfile = {};   // base64 pubkey → {username, display_name} from registry
let _nodeIdToProfile = {}; // node_id → {handle, display_name} from registry
const _pendingNodeLookups = new Set();

function _isNodeId(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

function _lookupNodeFromRegistry(nodeId) {
  if (_nodeIdToProfile[nodeId] !== undefined || _pendingNodeLookups.has(nodeId)) return;
  _pendingNodeLookups.add(nodeId);
  apiFetch('/api/registry/node/' + encodeURIComponent(nodeId))
    .then(r => r.ok ? r.json() : null)
    .then(d => {
      _nodeIdToProfile[nodeId] = d || {};
      _pendingNodeLookups.delete(nodeId);
      if (d?.display_name || d?.handle) _rerenderVisibleAuthorNames();
    })
    .catch(() => { _nodeIdToProfile[nodeId] = {}; _pendingNodeLookups.delete(nodeId); });
}
let _pendingKeyLookups = new Set();

// ── profile hover popup ────────────────────────────────────────────────────
function _showProfilePopup(serverUrl, anchorEl) {
  document.querySelectorAll('.profile-popup').forEach(p => p.remove());
  const prof = serverProfiles[serverUrl] || {};
  const contact = (CFG?.contacts || []).find(c => c.url === serverUrl);
  const isOwn = serverUrl === CFG?.own_server;
  const name = prof.display_name || contact?.name || (isOwn ? (CFG?.own_display_name || 'Me') : (prof.handle ? '@'+prof.handle : serverUrl));
  const handle = prof.handle || contact?.handle;
  const photoUrl = prof.photo_url;
  const initials = (name[0] || '?').toUpperCase();
  const imgSize = 'calc(3em * 1.4)';
  const avatarStyle = `width:${imgSize};height:${imgSize};border-radius:50%;flex-shrink:0`;

  const popup = document.createElement('div');
  popup.className = 'profile-popup mention-popup';
  popup.onmouseenter = () => clearTimeout(_avatarHideTimer);
  popup.onmouseleave = () => { _avatarHideTimer = setTimeout(() => popup.remove(), 100); };

  const row = document.createElement('div');
  row.style.cssText = 'display:flex;gap:0.65rem;align-items:center;margin-bottom:0.5rem';
  if (photoUrl) {
    const img = document.createElement('img');
    img.src = photoUrl; img.style.cssText = avatarStyle + ';object-fit:cover';
    img.onerror = () => { const d = document.createElement('div'); d.style.cssText = avatarStyle + ';background:var(--avatar-bg);display:flex;align-items:center;justify-content:center;font-size:1.1rem;color:var(--avatar-text)'; d.textContent = initials; img.replaceWith(d); };
    row.appendChild(img);
  } else {
    const d = document.createElement('div');
    d.style.cssText = avatarStyle + ';background:var(--avatar-bg);display:flex;align-items:center;justify-content:center;font-size:1.1rem;color:var(--avatar-text)';
    d.textContent = initials; row.appendChild(d);
  }
  const info = document.createElement('div'); info.style.minWidth = '0';
  const nameEl = document.createElement('div');
  nameEl.style.cssText = 'font-size:0.95rem;font-weight:500;color:var(--text-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis';
  nameEl.textContent = name; info.appendChild(nameEl);
  if (handle) { const hEl = document.createElement('div'); hEl.style.cssText = 'font-size:0.8rem;color:var(--text-5)'; hEl.textContent = '@' + handle; info.appendChild(hEl); }
  row.appendChild(info); popup.appendChild(row);

  if (!isOwn) {
    const btns = document.createElement('div'); btns.style.cssText = 'display:flex;gap:0.35rem;margin-top:0.35rem';
    const dmBtn = document.createElement('button');
    dmBtn.className = 'btn btn-muted btn-sm'; dmBtn.style.fontSize = '0.8rem'; dmBtn.textContent = '✉'; dmBtn.title = 'Send message';
    dmBtn.onclick = e => { e.stopPropagation(); popup.remove(); _dmStartNew(serverUrl); };
    btns.appendChild(dmBtn);
    if (!contact) {
      const addBtn = document.createElement('button');
      addBtn.className = 'btn btn-muted btn-sm'; addBtn.style.fontSize = '0.8rem'; addBtn.textContent = '+👤'; addBtn.title = 'Add as contact';
      addBtn.onclick = e => { e.stopPropagation(); popup.remove(); openAddContact(); const inp = document.getElementById('add-contact-handle'); if (inp) { inp.value = serverUrl; scheduleContactSearch(serverUrl); } };
      btns.appendChild(addBtn);
    }
    popup.appendChild(btns);
  }

  document.body.appendChild(popup);
  const r = anchorEl.getBoundingClientRect();
  popup.style.visibility = 'hidden';
  requestAnimationFrame(() => {
    const pw = popup.offsetWidth;
    popup.style.top = (r.bottom + 6 + window.scrollY) + 'px';
    popup.style.left = Math.max(4, Math.min(r.left + window.scrollX, window.innerWidth - pw - 8)) + 'px';
    popup.style.visibility = '';
  });
}

let _avatarHideTimer = null;
(function() {
  let _hoverTimer = null;
  document.addEventListener('mouseover', e => {
    const av = e.target.closest('.post-author-avatar');
    if (!av) return;
    clearTimeout(_hoverTimer); clearTimeout(_avatarHideTimer);
    const serverUrl = av.closest('[data-server]')?.dataset.server || '';
    _hoverTimer = setTimeout(() => _showProfilePopup(serverUrl, av), 300);
  });
  document.addEventListener('mouseout', e => {
    const av = e.target.closest('.post-author-avatar');
    if (!av) return;
    clearTimeout(_hoverTimer);
    _avatarHideTimer = setTimeout(() => document.querySelectorAll('.profile-popup').forEach(p => p.remove()), 150);
  });
})();

// ── emoji hover preview ────────────────────────────────────────────────────
let _hideEmojiPreview = () => {};  // overwritten by IIFE below
(function() {
  let _session = 0;   // incremented on each hide; retries check this to self-cancel
  let _activeBtn = null;
  _hideEmojiPreview = () => {
    _session++;
    _activeBtn = null;
    const el = document.getElementById('emoji-preview');
    if (el) el.hidden = true;
  };
  const _REACT = ['reaction-btn', 'reaction-btn-active'];
  const _ALL   = [..._REACT, 'emoji-pick-btn'];
  document.addEventListener('mouseover', e => {
    const btn = e.target.closest('.' + _ALL.join(',.'));
    if (!btn || btn === _activeBtn) return;
    _activeBtn = btn;
    const mySession = ++_session;
    const emojiEl = document.getElementById('emoji-preview-char');
    const namesEl = document.getElementById('emoji-preview-names');
    const el = document.getElementById('emoji-preview');
    if (!emojiEl || !el) return;
    const emoji = (btn.childNodes[0]?.textContent || btn.textContent || '').trim().split(/\s/)[0];
    if (!emoji) return;
    emojiEl.textContent = emoji;
    const isReaction = _REACT.some(c => btn.classList.contains(c));
    if (isReaction && namesEl) {
      const reactors = JSON.parse(btn.dataset.reactors || '[]');
      const serverUrl = btn.dataset.server || '';
      if (reactors.length) {
        namesEl.textContent = reactors.map(id => _reactorName(id, serverUrl)).join('\n');
        namesEl.hidden = false;
        let n = 0;
        const retry = () => {
          if (_session !== mySession || n++ > 5) return;  // stale session — stop
          const upd = reactors.map(id => _reactorName(id, serverUrl)).join('\n');
          if (upd !== namesEl.textContent) namesEl.textContent = upd;
          setTimeout(retry, 600 * n);
        };
        setTimeout(retry, 600);
      } else {
        namesEl.hidden = true;
      }
    } else if (namesEl) {
      namesEl.hidden = true;
    }
    el.hidden = false;
  });
  document.addEventListener('mouseout', e => {
    const btn = e.target.closest('.' + _ALL.join(',.'));
    if (!btn) return;
    if (btn.contains(e.relatedTarget)) return;  // cursor moved to child element, stay open
    _session++;   // invalidate any pending retries from the previous hover
    _activeBtn = null;
    document.getElementById('emoji-preview').hidden = true;
  });
  document.addEventListener('mousemove', e => {
    if (!_activeBtn) return;
    const el = document.getElementById('emoji-preview');
    const vw = window.innerWidth, vh = window.innerHeight;
    el.style.left = Math.min(e.clientX + 12, vw - 200) + 'px';
    el.style.top  = Math.max(e.clientY - 90, 4) + 'px';
  });
})();

// ── client session token ───────────────────────────────────────────────────
function getClientToken() { return localStorage.getItem("contacc_client_session"); }
function setClientToken(t) { localStorage.setItem("contacc_client_session", t); }
function clearClientToken() { localStorage.removeItem("contacc_client_session"); }

function apiHeaders(extra = {}) {
  const t = getClientToken();
  return t ? {"Authorization": "Bearer " + t, ...extra} : extra;
}
async function apiFetch(url, opts = {}) {
  opts.headers = {...apiHeaders(), ...(opts.headers || {})};
  let r = await fetch(url, opts);
  if (r.status === 401) {
    // Session may have been wiped by a server restart — try to re-bootstrap
    const s = await fetch("/client/session", {method: "POST"});
    if (s.ok) {
      setClientToken((await s.json()).token);
      opts.headers = {...apiHeaders(), ...(opts.headers || {})};
      r = await fetch(url, opts);
    }
  }
  return r;
}

function clientTokenParam(hasExistingQuery) {
  const t = getClientToken();
  if (!t) return "";
  return (hasExistingQuery ? "&" : "?") + "client_token=" + encodeURIComponent(t);
}

// ── init ───────────────────────────────────────────────────────────────────
(async function init() {
  await continueInit();
})();

async function continueInit() {
  // Check server setup state before anything else
  try {
    const sr = await fetch("/setup/status");
    if (sr.ok) {
      const ss = await sr.json();
      if (ss.state === "uninitialized") {
        showView("setup");
        const _up = new URLSearchParams(location.search);
        const _proxyStep = _up.get("proxy_step");
        const _proxyToken = _up.get("proxy_token");
        const _setupTok = _up.get("setup_token");
        if (_proxyStep === "identity" && _proxyToken && _setupTok) {
          history.replaceState({}, "", "/");
          await _handleSetupProxyIdentity(_proxyToken, _setupTok);
        } else if (_setupTok) {
          document.getElementById("setup-token-input").value = _setupTok;
          acceptSetupToken();
        }
        return;
      }
      if (ss.state === "locked") { showView("unlock"); return; }
    }
  } catch {}

  let r = await apiFetch("/api/config");
  if (r.status === 401) {
    // Try to bootstrap a session from the stored server owner token
    const s = await fetch("/client/session", {method: "POST"});
    if (s.ok) {
      setClientToken((await s.json()).token);
      r = await apiFetch("/api/config");
    } else {
      if (s.status === 403) {
        document.getElementById("login-error").textContent = "Owner access required.";
      }
      showView("login");
      return;
    }
  }
  const _rawCfg = await r.json().catch(() => null);
  if (!_rawCfg) { document.getElementById("login-error").textContent = "Could not load config."; showView("login"); return; }
  _setCFG(_rawCfg);

  document.getElementById("login-server").textContent = CFG.own_server;

  const status = CFG.servers.find(s => s.url === CFG.own_server);
  if (status && status.authenticated) {
    await loadFeed();
  } else {
    showView("login");
  }
}

// ── auth ───────────────────────────────────────────────────────────────────
async function loginGoogle() {
  const returnTo = encodeURIComponent(window.location.origin + "/auth/callback");
  const r = await fetch("/client/login-url?return_to=" + returnTo);
  if (!r.ok) { document.getElementById("login-error").textContent = "Login unavailable."; return; }
  window.location.href = (await r.json()).auth_url;
}


let _mentionPopupTimer = null;

function _showMentionPopup(event, span) {
  clearTimeout(_mentionPopupTimer);
  _mentionPopupTimer = setTimeout(() => {
    document.querySelectorAll('.mention-popup').forEach(p => p.remove());
    const id = span.dataset.mentionId;
    const contact = (CFG?.contacts || []).find(c => c.node_id === id || c.public_key === id);
    if (!contact) return;
    const prof = serverProfiles[contact.url] || {};
    const name = prof.display_name || contact.name || '';
    const handle = contact.handle ? '@' + contact.handle : '';
    const initials = (name[0] || '?').toUpperCase();
    const imgSize = 'calc(3em * 1.4)';
    const avatarStyle = `width:${imgSize};height:${imgSize};border-radius:50%;flex-shrink:0`;

    const popup = document.createElement('div');
    popup.className = 'mention-popup';
    popup.onmouseenter = () => clearTimeout(_mentionPopupTimer);
    popup.onmouseleave = () => _hideMentionPopup();

    // Build layout
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:0.65rem;align-items:center';

    // Avatar — try photo, fall back to initials on error
    const makeInitials = () => {
      const d = document.createElement('div');
      d.style.cssText = avatarStyle + ';background:var(--avatar-bg);display:flex;align-items:center;justify-content:center;font-size:1.1rem;color:var(--avatar-text)';
      d.textContent = initials;
      return d;
    };
    const photoUrl = contact.node_id ? '/api/contacts/photo?node_id=' + encodeURIComponent(contact.node_id) : '';
    const img = document.createElement('img');
    img.src = photoUrl;
    img.style.cssText = avatarStyle + ';object-fit:cover';
    img.onerror = () => img.replaceWith(makeInitials());
    row.appendChild(img);

    const info = document.createElement('div');
    info.style.minWidth = '0';
    const nameEl = document.createElement('div');
    nameEl.style.cssText = 'font-size:0.95rem;font-weight:500;color:#e0e0e0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis';
    nameEl.textContent = name;
    info.appendChild(nameEl);
    if (handle) {
      const hEl = document.createElement('div');
      hEl.style.cssText = 'font-size:0.8rem;color:#666';
      hEl.textContent = handle;
      info.appendChild(hEl);
    }
    row.appendChild(info);
    popup.appendChild(row);

    const btns = document.createElement('div'); btns.style.cssText = 'display:flex;gap:0.35rem;margin-top:0.35rem';
    const dmBtn = document.createElement('button');
    dmBtn.className = 'btn btn-muted btn-sm'; dmBtn.style.fontSize = '0.8rem'; dmBtn.textContent = '✉'; dmBtn.title = 'Send message';
    dmBtn.onclick = e => { e.stopPropagation(); popup.remove(); _dmStartNew(contact.url); };
    btns.appendChild(dmBtn);
    popup.appendChild(btns);

    document.body.appendChild(popup);
    const sr = span.getBoundingClientRect();
    popup.style.visibility = 'hidden';
    requestAnimationFrame(() => {
      const pw = popup.offsetWidth;
      const top = sr.bottom + 6 + window.scrollY;
      const left = Math.min(sr.left + window.scrollX, window.innerWidth - pw - 8);
      popup.style.top = top + 'px';
      popup.style.left = Math.max(4, left) + 'px';
      popup.style.visibility = '';
    });
  }, 200);
}

function _hideMentionPopup(event) {
  clearTimeout(_mentionPopupTimer);
  _mentionPopupTimer = setTimeout(() => {
    document.querySelectorAll('.mention-popup').forEach(p => p.remove());
  }, 100);
}

function _toggleSidebar() {
  const body = document.getElementById("sidebar-body");
  const arrow = document.getElementById("sidebar-toggle-arrow");
  const open = body.classList.toggle("open");
  arrow.textContent = open ? "▾" : "▸";
}

async function logout() {
  await apiFetch("/api/auth/token", {method: "DELETE"});
  clearClientToken();
  CFG = null;
  location.reload();
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  _updateThemeButtons();
}

function _updateThemeButtons() {
  const theme = document.documentElement.getAttribute('data-theme') || 'dark';
  const darkBtn = document.getElementById('theme-btn-dark');
  const lightBtn = document.getElementById('theme-btn-light');
  if (darkBtn) { darkBtn.style.background = theme === 'dark' ? 'var(--accent-surface)' : ''; darkBtn.style.color = theme === 'dark' ? 'var(--accent-light)' : ''; }
  if (lightBtn) { lightBtn.style.background = theme === 'light' ? 'var(--accent-surface)' : ''; lightBtn.style.color = theme === 'light' ? 'var(--accent-light)' : ''; }
}

async function loadIdentity() {
  const r = await apiFetch("/api/auth/me");
  if (!r.ok) return;
  const d = await r.json();
  IS_OWNER = d.role === "owner";
  document.getElementById("compose-btn").hidden = true; // replaced by inline compose
  document.getElementById("inline-compose").hidden = !IS_OWNER;
  const identity = d.identity || "";
  const nodeR = await fetch("/node");
  const nodeD = nodeR.ok ? await nodeR.json() : {};
  const handle = nodeD.handle || "";
  document.getElementById("handle-display").textContent = handle ? `@${handle}` : "";
  if (handle) document.title = `@${handle}`;
  if (IS_OWNER) {
    loadProfileAvatar();
  }
}

async function loadProfileAvatar() {
  try {
    const r = await apiFetch("/api/profile");
    if (!r.ok) return;
    const p = await r.json();
    const avatarImg = document.getElementById("profile-avatar");
    const avatarInit = document.getElementById("profile-avatar-initials");
    const initName = (p.display_name || p.handle || "?")[0].toUpperCase();
    if (p.photo_url) {
      avatarImg.onerror = () => { avatarImg.hidden = true; avatarInit.textContent = initName; avatarInit.hidden = false; };
      avatarImg.src = p.photo_url + "?t=" + Date.now();
      avatarImg.hidden = false;
      avatarInit.hidden = true;
    } else {
      avatarInit.textContent = initName;
      avatarInit.hidden = false;
      avatarImg.hidden = true;
    }
    document.getElementById("profile-display-name").value = p.display_name || "";
    if (p.display_name) {
      document.getElementById("handle-display").textContent = p.display_name;
      document.title = p.display_name;
    }
    const pkWrap = document.getElementById("profile-pubkey-wrap");
    if (p.public_key) {
      document.getElementById("profile-pubkey").textContent = p.public_key;
      pkWrap.hidden = false;
    } else {
      pkWrap.hidden = true;
    }
    const modalImg = document.getElementById("profile-modal-photo");
    const modalInit = document.getElementById("profile-modal-initials");
    if (p.photo_url) {
      modalImg.onerror = () => { modalImg.hidden = true; modalInit.textContent = initName; modalInit.hidden = false; };
      modalImg.src = p.photo_url + "?t=" + Date.now();
      modalImg.hidden = false;
      modalInit.hidden = true;
    } else {
      modalInit.textContent = initName;
      modalInit.hidden = false;
      modalImg.hidden = true;
    }
  } catch {}
}

// ── views ──────────────────────────────────────────────────────────────────
function showView(name) {
  document.getElementById("setup-view").hidden        = name !== "setup";
  document.getElementById("identity-key-view").hidden = name !== "identity-key";
  document.getElementById("unlock-view").hidden       = name !== "unlock";
  document.getElementById("login-view").hidden        = name !== "login";
  document.getElementById("feed-view").hidden         = name !== "feed";
}

// ── server sidebar ─────────────────────────────────────────────────────────
function renderServerList() {
  const list = document.getElementById("server-list");
  const allBtn = '<button class="server-btn' + (activeServer === null ? " active" : "") + '" onclick="setActiveServer(-1)"><span>All</span></button>';
  const contacts = (CFG.servers || []).filter(s => s.url !== CFG.own_server);
  const serverBtns = contacts.map((s, i) => {
    const globalIdx = (CFG.servers || []).indexOf(s);
    const status = serverStatuses[s.url] || "wait";
    const prof = serverProfiles[s.url];
    const label = esc(_authorName(s.url));
    const sInitial = esc((s.name||'?')[0].toUpperCase());
    const avatarHtml = prof && prof.photo_url
      ? `<img src="${esc(prof.photo_url)}" class="post-author-avatar" alt="" onerror="this.hidden=true;this.nextElementSibling.hidden=false"><span class="post-author-initials" hidden>${sInitial}</span>`
      : `<span class="post-author-initials">${sInitial}</span>`;
    const tagLabel = s.tag || s.name.trim().split(/\s+/)[0] || s.handle || '';
    const urlJson  = JSON.stringify(s.url).replace(/"/g, '&quot;');
    return '<div class="contact-row" data-server="' + esc(s.url) + '">'
      + '<button class="server-btn' + (activeServer === s.url ? " active" : "") + '" onclick="setActiveServer(' + globalIdx + ')" title="' + esc(tagLabel ? '@' + tagLabel : s.name) + '">'
      + avatarHtml
      + '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + label + '</span>'
      + '<span class="server-dot ' + status + '"></span>'
      + '</button>'
      + '<span style="position:relative;display:inline-flex;align-items:center">'
      + '<button class="contact-menu-btn" onclick="openContactMenu(event,' + urlJson + ')" title="Contact options">…</button>'
      + '</span>'
      + '</div>';
  });
  list.innerHTML = allBtn + serverBtns.join("");
}

const _CONTACT_CATS = [
  {key:'family',        label:'Family',    weight:1.0},
  {key:'close_friends', label:'Close',     weight:0.8},
  {key:'friends',       label:'Friends',   weight:0.6},
  {key:'colleagues',    label:'Work',      weight:0.5},
  {key:'acquaintances', label:'Acquaint.', weight:0.3},
];

function openContactMenu(e, url) {
  e.stopPropagation();
  closeAllPostMenus();
  const btn = e.currentTarget;
  const wrap = btn.parentElement;
  const popup = document.createElement('div');
  popup.className = 'post-menu-popup';
  popup.style.cssText = 'display:flex;flex-direction:row;padding:0.15rem;gap:1px;min-width:0';

  const items = [
    { icon: '✉️', title: 'Message',        onclick: () => { closeAllPostMenus(); _dmStartNew(url); } },
    { icon: '✏️',  title: 'Edit contact',   onclick: () => { closeAllPostMenus(); openContactEdit(url); } },
    { icon: '🗑️', title: 'Remove contact', onclick: () => { closeAllPostMenus(); removeContact(url); }, danger: true },
  ];
  for (const item of items) {
    const b = document.createElement('button');
    b.textContent = item.icon;
    b.title = item.title;
    b.style.cssText = 'font-size:1.05rem;padding:0.25rem 0.4rem;background:none;border:none;cursor:pointer;border-radius:4px;line-height:1';
    b.style.color = item.danger ? 'var(--error)' : 'var(--text-2)';
    b.onmouseenter = () => b.style.background = 'var(--surface-3)';
    b.onmouseleave = () => b.style.background = 'none';
    b.onclick = item.onclick;
    popup.appendChild(b);
  }

  wrap.appendChild(popup);
  const dismiss = ev => { if (!popup.contains(ev.target) && ev.target !== btn) { closeAllPostMenus(); document.removeEventListener('click', dismiss, true); } };
  setTimeout(() => document.addEventListener('click', dismiss, true), 0);
}

async function setContactTag(url, currentTag) {
  const newTag = prompt("@mention tag for this contact (e.g. Tox):", currentTag);
  if (newTag === null) return;
  const r = await apiFetch("/api/contacts", {
    method: "PATCH",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({url, tag: newTag.trim()}),
  });
  if (!r.ok) { alert("Failed to set tag."); return; }
  const cfg = await (await apiFetch("/api/config")).json();
  _setCFG(cfg);
  renderServerList();
}


async function editContactDescription(url, currentDescription) {
  const newDesc = prompt("Description for this contact:", currentDescription || "");
  if (newDesc === null) return;
  const r = await apiFetch("/api/contacts", {
    method: "PATCH",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({url, description: newDesc.trim()}),
  });
  if (!r.ok) { alert("Failed to save description."); return; }
  const cfg = await (await apiFetch("/api/config")).json();
  _setCFG(cfg);
}

async function removeContact(url) {
  if (!confirm("Remove this contact?")) return;
  const r = await apiFetch("/api/contacts?" + new URLSearchParams({url}), {method: "DELETE"});
  if (!r.ok) { alert("Failed to remove contact."); return; }
  if (activeServer === url) setActiveServer(-1);
  const cfg = await (await apiFetch("/api/config")).json();
  _setCFG(cfg);
  renderServerList();
}

function _isPublicKey(s) {
  // base64url/base64 strings of ~44 chars that aren't URLs
  if (!s || s.startsWith("http") || s.startsWith("google:") || s === "__anon__") return false;
  return /^[A-Za-z0-9+/=_-]{32,}$/.test(s);
}

function _lookupKeyFromRegistry(identity) {
  const cached = _keyToProfile[identity];
  if (_pendingKeyLookups.has(identity)) return;
  // Only skip if we have useful cached data (not just an empty {} from a failed lookup)
  if (cached && (cached.display_name || cached.username || cached.server_url)) return;
  _pendingKeyLookups.add(identity);
  const registryUrl = (CFG.identity_proxy_url || "").replace(/\/$/, "");
  if (!registryUrl) { _pendingKeyLookups.delete(identity); return; }
  let url;
  if (identity.startsWith("http://") || identity.startsWith("https://")) {
    // URL identity — fetch the node's public key then look up in registry
    const nodeUrl = identity + "/node";
    fetch(nodeUrl).then(r => r.ok ? r.json() : null).then(d => {
      if (d?.public_key) {
        serverPublicKeys[d.public_key] = identity;
        return fetch(registryUrl + "/lookup-by-key?public_key=" + encodeURIComponent(d.public_key))
          .then(r2 => r2.ok ? r2.json() : null);
      }
      return null;
    }).then(d => {
      _keyToProfile[identity] = d || {};
      _rerenderVisibleAuthorNames();
    }).catch(() => { _keyToProfile[identity] = {}; }).finally(() => _pendingKeyLookups.delete(identity));
  } else {
    // raw public key
    fetch(registryUrl + "/lookup-by-key?public_key=" + encodeURIComponent(identity))
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d && d.server_url) serverPublicKeys[identity] = d.server_url;
        _keyToProfile[identity] = d || {};
        _rerenderVisibleAuthorNames();
      })
      .catch(() => { _keyToProfile[identity] = {}; })
      .finally(() => _pendingKeyLookups.delete(identity));
  }
}

function _rerenderVisibleAuthorNames() {
  if (_reactorTooltipBtn) _showReactorTooltip({ }, _reactorTooltipBtn);
}

async function fetchServerHandles() {
  for (const s of CFG.servers || []) {
    try {
      const nodeUrl = s.url === CFG.own_server ? "/node" : s.url + "/node";
      const r = await fetch(nodeUrl);
      if (r.ok) {
        const d = await r.json();
        if (d.handle) { serverHandles[s.url] = d.handle; renderServerList(); }
        if (d.public_key && serverPublicKeys[d.public_key] !== s.url) {
          serverPublicKeys[d.public_key] = s.url;
          _rerenderVisibleAuthorNames();
        }
        const activity7d = d.posts_7d || 0;
        _serverActivity7d[s.url] = activity7d;
        const contact = (CFG.servers || []).find(c => c.url === s.url);
        _serverPollIntervals[s.url] = _computePollInterval(activity7d, contact?.poll_weight);
      }
    } catch {}
  }
}

async function fetchServerProfiles() {
  const servers = [CFG.own_server, ...(CFG.contacts || []).map(c => c.url).filter(Boolean)];
  // Seed from server (authoritative — knows what's actually on disk) + localStorage
  // cachedPhotos is keyed by node_id; filter out legacy URL-shaped entries from localStorage
  const cachedPhotos = new Set([
    ...(CFG.cached_photos || []),
    ...JSON.parse(localStorage.getItem('cachedContactPhotos') || '[]').filter(x => !x.startsWith('http')),
  ]);
  // url→node_id map for photo cache keying during profile fetch
  const urlToNodeId = {};
  for (const c of (CFG.contacts || [])) { if (c.url && c.node_id) urlToNodeId[c.url] = c.node_id; }

  // Pre-seed contacts from local config so names show even when offline;
  // only set photo_url if we've previously confirmed a cached photo exists.
  for (const c of (CFG.contacts || [])) {
    if (!serverProfiles[c.url]) {
      serverProfiles[c.url] = {
        display_name: c.name,
        handle: c.handle,
        photo_url: c.node_id && cachedPhotos.has(c.node_id) ? "/api/contacts/photo?node_id=" + encodeURIComponent(c.node_id) : null,
      };
    }
  }

  await Promise.all(servers.map(async url => {
    try {
      const r = url === CFG.own_server
        ? await apiFetch("/api/profile")
        : await fetch(url + "/profile");
      if (r.ok) {
        const profile = await r.json();
        if (url !== CFG.own_server) {
          const nid = urlToNodeId[url];
          const proxyUrl = nid ? "/api/contacts/photo?node_id=" + encodeURIComponent(nid) : null;
          if (profile.photo_url && proxyUrl) {
            fetch(proxyUrl).catch(() => {}); // warm the cache
            profile.photo_url = proxyUrl;
            if (nid && !cachedPhotos.has(nid)) {
              cachedPhotos.add(nid);
              localStorage.setItem('cachedContactPhotos', JSON.stringify([...cachedPhotos]));
            }
          } else {
            if (nid && cachedPhotos.has(nid)) {
              cachedPhotos.delete(nid);
              localStorage.setItem('cachedContactPhotos', JSON.stringify([...cachedPhotos]));
            }
            profile.photo_url = null;
          }
        }
        // Populate user_id from /node if not already in profile or contact entry
        if (!profile.node_id && url !== CFG.own_server) {
          try {
            const nr = await fetch(url + "/node");
            if (nr.ok) {
              const nd = await nr.json();
              if (nd.user_id) {
                profile.node_id = nd.node_id || nd.user_id;
                // Also backfill the contact entry so mentions work without re-add
                const c = (CFG.contacts || []).find(c => c.url === url);
                if (c && !c.node_id) c.node_id = nd.user_id;
              }
            }
          } catch {}
        }
        serverProfiles[url] = profile;
        serverStatuses[url] = "ok";
        _saveProfileCache();
        renderServerList();
        document.querySelectorAll(".post-author").forEach(el => {
          if (el.dataset.server === url) _renderAuthorInto(el, url);
        });
        _rerenderVisibleAuthorNames();
      }
    } catch {}
  }));
}

function _authorName(url) {
  if (url === CFG.own_server) return "me";
  return _resolveIdentity(url, url).name;
}

function _renderAuthorInto(el, url) {
  const p = serverProfiles[url];
  const name = _authorName(url);
  const handle = p?.handle || serverHandles[url];
  el.title = handle ? `@${handle}` : name;
  const right = el.querySelector('.post-author-right');
  el.innerHTML = "";
  const left = document.createElement("span");
  left.style.cssText = "display:inline-flex;align-items:center;gap:0.4rem;min-width:0";
  if (p?.photo_url) {
    const img = document.createElement("img");
    img.src = p.photo_url;
    img.className = "post-author-avatar";
    img.alt = name;
    img.onerror = () => {
      const init = document.createElement("div");
      init.className = "post-author-initials";
      init.textContent = name[0].toUpperCase();
      img.replaceWith(init);
    };
    left.appendChild(img);
  } else {
    const init = document.createElement("div");
    init.className = "post-author-initials";
    init.textContent = name[0].toUpperCase();
    left.appendChild(init);
  }
  const nameEl = document.createElement("span");
  nameEl.className = "post-author-name";
  nameEl.textContent = name;
  left.appendChild(nameEl);
  el.appendChild(left);
  if (right) el.appendChild(right);
}

function setActiveServer(i) {
  if (i === -1) {
    activeServer = null;
  } else {
    const url = CFG.servers[i].url;
    activeServer = (activeServer === url) ? null : url;
  }
  renderServerList();
  resetFeed();
}

function filterOwnPosts() {
  activeServer = (activeServer === CFG.own_server) ? null : CFG.own_server;
  renderServerList();
  resetFeed();
}

// ── add contact ────────────────────────────────────────────────────────────
let _pendingContact = null;

function openAddContact() {
  document.getElementById("add-contact-handle").value = "";
  document.getElementById("add-contact-result").textContent = "";
  document.getElementById("add-contact-error").textContent = "";
  document.getElementById("add-contact-results-list").innerHTML = "";
  document.getElementById("add-contact-card").hidden = true;
  document.getElementById("add-contact-confirm").hidden = true;
  document.getElementById("add-contact-overlay").hidden = false;
  document.getElementById("add-contact-handle").focus();
  _pendingContact = null;
}
function closeAddContact() { document.getElementById("add-contact-overlay").hidden = true; }

let _contactSearchTimer = null;
function scheduleContactSearch(val) {
  clearTimeout(_contactSearchTimer);
  _contactSearchTimer = setTimeout(() => searchContacts(val), 300);
}

async function searchContacts(val) {
  const q = (val !== undefined ? val : document.getElementById("add-contact-handle").value).trim();
  const result = document.getElementById("add-contact-result");
  const list = document.getElementById("add-contact-results-list");
  const card = document.getElementById("add-contact-card");
  const confirm = document.getElementById("add-contact-confirm");
  document.getElementById("add-contact-error").textContent = "";
  card.hidden = true;
  confirm.hidden = true;
  list.innerHTML = "";
  _pendingContact = null;
  if (!q) { result.textContent = ""; return; }
  result.textContent = "Searching…";
  const r = await apiFetch("/api/contacts/search?q=" + encodeURIComponent(q));
  if (!r.ok) { result.textContent = "Search failed."; return; }
  const data = await r.json();
  const results = (data.results || []).filter(d => d.server_url !== CFG.own_server);
  result.textContent = results.length ? "" : "No matches found.";
  list.innerHTML = results.map((d, i) => {
    const name = d.display_name || ("@" + d.username) || d.server_url;
    const handle = d.username ? "@" + d.username : "";
    const rInitial = esc((name[0]||'?').toUpperCase());
    const avatar = d.photo_url
      ? `<img class="contact-search-result-avatar" src="${esc(d.photo_url)}" alt="" onerror="this.hidden=true;this.nextElementSibling.hidden=false"><div class="contact-search-result-initials" hidden>${rInitial}</div>`
      : `<div class="contact-search-result-initials">${rInitial}</div>`;
    return `<div class="contact-search-result" onclick="selectContactResult(${i})" data-idx="${i}">
      ${avatar}
      <div><div class="contact-search-result-name">${esc(name)}</div>${handle ? `<div class="contact-search-result-handle">${esc(handle)}</div>` : ''}</div>
    </div>`;
  }).join("");
  list._results = results;
}

function selectContactResult(idx) {
  const list = document.getElementById("add-contact-results-list");
  const d = list._results && list._results[idx];
  if (!d) return;
  list.innerHTML = "";
  _pendingContact = {
    handle: d.username || null,
    display_name: d.display_name || null,
    server_url: d.server_url,
    photo_url: d.photo_url || null,
    public_key: d.public_key || null,
    node_id: d.node_id || d.user_id || null,
  };
  const photoEl = document.getElementById("add-contact-photo");
  const initEl  = document.getElementById("add-contact-initials");
  const nameEl  = document.getElementById("add-contact-display-name");
  const hndlEl  = document.getElementById("add-contact-handle-display");
  const displayName = d.display_name || (d.username ? "@" + d.username : d.server_url);
  nameEl.textContent = displayName;
  hndlEl.textContent = d.username ? "@" + d.username : "";
  if (d.photo_url) {
    photoEl.onerror = () => { photoEl.hidden = true; initEl.textContent = displayName[0].toUpperCase(); initEl.hidden = false; };
    photoEl.src = d.photo_url;
    photoEl.hidden = false;
    initEl.hidden = true;
  } else {
    initEl.textContent = displayName[0].toUpperCase();
    initEl.hidden = false;
    photoEl.hidden = true;
  }
  document.getElementById("add-contact-card").hidden = false;
  document.getElementById("add-contact-confirm").hidden = false;
}

async function confirmAddContact() {
  if (!_pendingContact) return;
  const name = _pendingContact.display_name || _pendingContact.handle;
  const err = document.getElementById("add-contact-error");
  err.textContent = "";
  const r = await apiFetch("/api/contacts", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({name, url: _pendingContact.server_url, handle: _pendingContact.handle || null, public_key: _pendingContact.public_key || null, node_id: _pendingContact.node_id || null}),
  });
  if (r.status === 409) { err.textContent = "Already in your contacts."; return; }
  if (!r.ok) { err.textContent = "Failed to add contact."; return; }
  closeAddContact();
  const cfg = await (await apiFetch("/api/config")).json();
  _setCFG(cfg);
  renderServerList();
  fetchServerHandles();
  fetchServerProfiles();
  resetFeed();
}

// ── tag sidebar ────────────────────────────────────────────────────────────
async function loadTagSidebar() {
  const freq = {};

  // Count tags from contact-server posts already loaded in memory
  for (const post of allPosts) {
    if ((post._server_url || CFG.own_server) === CFG.own_server) continue;
    for (const tag of (post.tags || [])) freq[tag] = (freq[tag] || 0) + 1;
  }

  // Add complete own-server tag counts from API (not limited to loaded posts)
  const r = await apiFetch("/api/tags");
  if (r.ok) {
    for (const {tag, count} of (await r.json()).tags || []) {
      freq[tag] = (freq[tag] || 0) + count;
    }
  }

  const sorted = Object.entries(freq).sort(([a, ca], [b, cb]) => {
    const aActive = activeTags.has(a) ? 1 : 0;
    const bActive = activeTags.has(b) ? 1 : 0;
    if (aActive !== bActive) return bActive - aActive;
    if (cb !== ca) return cb - ca;
    return a.localeCompare(b);
  });

  const list = document.getElementById("tag-list");
  list.innerHTML = sorted.map(([tag, count]) =>
    `<button class="tag-btn${activeTags.has(tag) ? " active" : ""}" onclick="toggleTag('${esc(tag)}')">`
    + `<span>${esc(tag)}</span><span class="tc">${count}</span></button>`
  ).join("");
}

function toggleTag(tag) {
  if (activeTags.has(tag)) activeTags.delete(tag); else activeTags.add(tag);
  document.getElementById("clear-tags-btn").hidden = activeTags.size === 0;
  document.querySelectorAll(".tag-btn").forEach(b => {
    b.classList.toggle("active", activeTags.has(b.querySelector("span:first-child").textContent));
  });
  resetFeed();
}
function clearTagFilter() {
  activeTags.clear();
  document.getElementById("clear-tags-btn").hidden = true;
  document.querySelectorAll(".tag-btn").forEach(b => b.classList.remove("active"));
  resetFeed();
}

// ── feed ───────────────────────────────────────────────────────────────────
function scheduleSearch(val) {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { currentSearch = val.trim() || null; resetFeed(); }, 350);
}

async function loadFeed() {
  showView("feed");
  renderServerList();
  checkDefaultPassphrase();
  checkEscrow();
  loadMentions();

  // Restore cached profiles so avatars show immediately without a flash.
  _loadProfileCache();

  // Render from cache immediately so the page is populated before any network calls.
  if (allPosts.length === 0 && !activeServer && !currentSearch && activeTags.size === 0) {
    const cached = _loadFeedCache();
    if (cached?.posts?.length) {
      const timeline = document.getElementById("timeline");
      for (const post of cached.posts) {
        post._is_stale = true;
        allPosts.push(post);
        const card = makePostCard(post, allPosts.length - 1);
        card.classList.add('post-stale');
        timeline.appendChild(card);
      }
      _newestKnownAt = cached.posts[0]?.created_at || 0;
      const n = allPosts.length;
      document.getElementById("feed-status").textContent = n + "+ posts (refreshing…)";
      document.getElementById("empty-msg").hidden = true;
    }
  }

  loadIdentity();
  loadTagSidebar();
  fetchServerHandles().then(() => _startBgFetch());
  fetchServerProfiles();
  _openSSE();

  if (allPosts.length === 0) {
    // No cache — block until we have something to show.
    const ok = await resetFeed(true);
    if (!ok) { showView("login"); return false; }
  } else {
    // Cache is warm — refresh from servers immediately in the background.
    const servers = activeServer ? [activeServer] : [CFG.own_server, ...(CFG.contacts || []).map(c => c.url)];
    for (const url of servers) _serverLastFetched[url] = 0;
    _runBgFetch().then(() => {
      const el = document.getElementById("feed-status");
      if (el && el.textContent.includes('refreshing')) {
        const n = allPosts.length;
        el.textContent = n ? n + " post" + (n !== 1 ? "s" : "") : "";
      }
    });
  }

  return true;
}

async function resetFeed(allowLoginRedirect = false) {
  nextCursor = null; allPosts = []; currentIdx = -1;
  document.getElementById("timeline").innerHTML = "";
  document.getElementById("empty-msg").hidden = true;
  document.getElementById("feed-status").textContent = "";
  return await loadMore(allowLoginRedirect);
}

async function loadMore(allowLoginRedirect = false) {
  let url = "/api/feed?limit=20";
  if (activeServer) url += "&server=" + encodeURIComponent(activeServer);
  if (nextCursor) url += "&cursor=" + encodeURIComponent(nextCursor);
  if (currentSearch) url += "&q=" + encodeURIComponent(currentSearch);
  for (const t of activeTags) url += "&tags=" + encodeURIComponent(t);

  const r = await apiFetch(url);
  if (r.status === 401) { if (allowLoginRedirect) showView("login"); return false; }
  if (!r.ok) return false;

  const data = await r.json();
  const src = activeServer || CFG.own_server;
  serverStatuses[src] = "ok";
  if (data.server_status) {
    for (const [url, status] of Object.entries(data.server_status)) {
      if (status === "online") serverOnline[url] = true;
      else if (status === "offline") serverOnline[url] = false;
      // "unknown" → leave unchanged so posts aren't incorrectly grayed out
    }
  }
  renderServerList();

  const timeline = document.getElementById("timeline");
  for (const post of data.posts) {
    allPosts.push(post);
    try {
      timeline.appendChild(makePostCard(post, allPosts.length - 1));
    } catch (err) {
      console.error('makePostCard failed:', err, post);
    }
  }
  if (!nextCursor && !currentSearch && activeTags.size === 0 && !activeServer) {
    _saveFeedCache(allPosts);
  }
  if (data.posts.length > 0) _newestKnownAt = Math.max(_newestKnownAt, data.posts[0].created_at || 0);
  nextCursor = data.next_cursor || null;
  document.getElementById("load-more-btn").hidden = !nextCursor;
  const n = allPosts.length;
  document.getElementById("feed-status").textContent = n
    ? n + (nextCursor ? "+" : "") + " post" + (n !== 1 ? "s" : "") : "";
  document.getElementById("empty-msg").hidden = n > 0;
  return true;
}

// ── reactions ──────────────────────────────────────────────────────────────
const REACTION_EMOJI = ['👍', '👎', '❤️', '😄', '😮', '😢', '🎉'];

// Full searchable emoji list: [emoji, name/keywords...]
// Loaded from unicode-emoji-json at startup; falls back to built-in list
let ALL_EMOJI = null;
async function _loadEmojiList() {
  if (ALL_EMOJI) return;
  try {
    const r = await fetch('https://cdn.jsdelivr.net/npm/unicode-emoji-json@0.6.0/data-by-emoji.json');
    if (r.ok) {
      const data = await r.json();
      ALL_EMOJI = Object.entries(data).map(([emoji, d]) => [emoji, ...(d.name || '').toLowerCase().split(/[\s_,]+/), ...(d.keywords || [])]);
      return;
    }
  } catch (_) {}
  ALL_EMOJI = _BUILTIN_EMOJI;
}
const _BUILTIN_EMOJI = [
  ['👍','thumbs up','like','good','yes','approve'],['👎','thumbs down','dislike','no','bad'],
  ['❤️','heart','love','red heart'],['🧡','orange heart'],['💛','yellow heart'],
  ['💚','green heart'],['💙','blue heart'],['💜','purple heart'],['🖤','black heart'],
  ['🤍','white heart'],['💕','two hearts'],['💞','revolving hearts'],['💗','growing heart'],
  ['💓','beating heart'],['💔','broken heart'],['😀','grinning'],['😃','grin'],
  ['😄','smile big eyes'],['😁','beaming'],['😆','laughing'],['😅','sweat smile'],
  ['🤣','rofl rolling floor laughing'],['😂','joy tears laughing'],['🙂','slightly smiling'],
  ['🙃','upside down'],['😉','winking'],['😊','smiling blush'],['😇','innocent halo'],
  ['🥰','smiling hearts'],['😍','heart eyes'],['🤩','star struck'],['😘','kiss'],
  ['😗','kissing'],['😚','kissing closed eyes'],['😙','kissing smiling'],['😋','yum'],
  ['😛','tongue'],['😜','winking tongue'],['🤪','zany'],['😝','squinting tongue'],
  ['🤑','money mouth'],['🤗','hugging'],['🤭','hand over mouth'],['🤫','shushing'],
  ['🤔','thinking'],['🤐','zipper mouth'],['🤨','raised eyebrow'],['😐','neutral'],
  ['😑','expressionless'],['😶','no mouth'],['😏','smirking'],['😒','unamused'],
  ['🙄','eye roll'],['😬','grimacing'],['🤥','lying pinocchio'],['😌','relieved'],
  ['😔','pensive'],['😪','sleepy'],['🤤','drooling'],['😴','sleeping'],
  ['😷','mask sick'],['🤒','thermometer sick'],['🤕','bandage hurt'],['🤢','nauseated'],
  ['🤮','vomiting'],['🤧','sneezing'],['🥵','hot'],['🥶','cold'],['🥴','woozy'],
  ['😵','dizzy'],['🤯','exploding head'],['🤠','cowboy'],['🥳','party celebrating'],
  ['😎','sunglasses cool'],['🤓','nerd glasses'],['🧐','monocle'],['😕','confused'],
  ['😟','worried'],['🙁','slightly frowning'],['😮','open mouth'],['😯','hushed'],
  ['😲','astonished'],['😳','flushed'],['🥺','pleading'],['😦','frowning open mouth'],
  ['😧','anguished'],['😨','fearful'],['😰','anxious sweat'],['😥','sad relieved'],
  ['😢','crying'],['😭','loudly crying'],['😱','screaming fear'],['😖','confounded'],
  ['😣','persevering'],['😞','disappointed'],['😓','downcast sweat'],['😩','weary'],
  ['😫','tired'],['🥱','yawning'],['😤','huffing'],['😡','pouting angry'],
  ['😠','angry'],['🤬','swearing'],['👿','imp angry'],['💀','skull death'],
  ['☠️','skull crossbones'],['💩','poop'],['🤡','clown'],['👹','ogre'],['👺','goblin'],
  ['👻','ghost'],['👽','alien'],['👾','space invader'],['🤖','robot'],
  ['😺','smiling cat'],['😸','grinning cat'],['😹','joy cat'],['😻','heart eyes cat'],
  ['😼','smirking cat'],['😽','kissing cat'],['🙀','weary cat'],['😿','crying cat'],
  ['😾','pouting cat'],['👋','wave hello'],['🤚','raised back hand'],['🖐️','hand splayed'],
  ['✋','raised hand'],['🖖','vulcan'],['👌','ok'],['🤌','pinched fingers'],
  ['✌️','peace victory'],['🤞','crossed fingers lucky'],['🤟','love you'],
  ['🤘','horns rock'],['🤙','call me shaka'],['👈','point left'],['👉','point right'],
  ['👆','point up'],['👇','point down'],['☝️','index up'],['👍','like'],
  ['👏','clapping applause'],['🙌','hands up'],['🤲','palms up'],['🤝','handshake'],
  ['🙏','pray thanks'],['✍️','writing'],['💪','muscle strong'],['🦵','leg'],
  ['🦶','foot'],['👂','ear'],['🦻','ear hearing aid'],['👃','nose'],
  ['🧠','brain'],['👀','eyes'],['👁️','eye'],['👅','tongue'],['👄','lips'],
  ['🌸','cherry blossom'],['🌹','rose'],['🌺','hibiscus'],['🌻','sunflower'],
  ['🌼','blossom'],['🍀','four leaf clover lucky'],['🎄','christmas tree'],
  ['🌈','rainbow'],['⭐','star'],['🌟','glowing star'],['💫','dizzy star'],
  ['⚡','lightning bolt'],['🔥','fire hot'],['❄️','snowflake cold'],['🌊','wave water'],
  ['🎉','party tada'],['🎊','confetti'],['🎈','balloon'],['🎁','gift present'],
  ['🏆','trophy winner'],['🥇','gold medal first'],['🎯','bullseye target'],
  ['🎮','video game controller'],['🎲','dice random'],['♟️','chess'],
  ['🍕','pizza'],['🍔','burger'],['🍟','fries'],['🌮','taco'],['🌯','burrito'],
  ['🍣','sushi'],['🍜','noodles ramen'],['🍦','ice cream'],['🍰','cake'],['🎂','birthday cake'],
  ['☕','coffee'],['🍵','tea'],['🧃','juice'],['🍺','beer'],['🥂','champagne toast'],
  ['🐶','dog'],['🐱','cat'],['🐭','mouse'],['🐹','hamster'],['🐰','rabbit'],
  ['🦊','fox'],['🐻','bear'],['🐼','panda'],['🐨','koala'],['🐯','tiger'],
  ['🦁','lion'],['🐮','cow'],['🐷','pig'],['🐸','frog'],['🐵','monkey'],
  ['🐔','chicken'],['🐧','penguin'],['🐦','bird'],['🦆','duck'],['🦅','eagle'],
  ['🦉','owl'],['🐺','wolf'],['🐗','boar'],['🐴','horse'],['🦄','unicorn'],
  ['🐝','bee'],['🦋','butterfly'],['🐌','snail'],['🐛','caterpillar'],['🐜','ant'],
  ['🦀','crab'],['🦞','lobster'],['🦐','shrimp'],['🦑','squid'],['🐙','octopus'],
  ['🌍','earth globe'],['🌙','moon'],['☀️','sun'],['🌤️','sun cloud'],
  ['👑','crown king queen'],['💎','diamond gem'],['🔑','key'],['🔒','lock'],
  ['🔓','unlock'],['⚙️','gear settings'],['🔧','wrench tool'],['💡','bulb idea'],
  ['📱','phone mobile'],['💻','laptop computer'],['⌨️','keyboard'],['🖥️','desktop'],
  ['📷','camera'],['🎵','music note'],['🎶','musical notes'],['🎤','microphone'],
  ['📚','books'],['📖','open book'],['✏️','pencil'],['📝','memo note'],
  ['💰','money bag'],['💸','flying money'],['💳','credit card'],['🏠','house home'],
  ['🚗','car'],['✈️','airplane'],['🚀','rocket'],['🛸','ufo'],
  ['⏰','alarm clock'],['⌛','hourglass'],['📅','calendar'],['📌','pushpin'],
  ['✅','check mark done'],['❌','cross no'],['❓','question'],['❗','exclamation'],
  ['💯','hundred percent'],['🆕','new'],['🆒','cool'],['🔝','top'],
  ['▶️','play'],['⏸️','pause'],['⏹️','stop'],['🔁','repeat'],['🔀','shuffle'],
  ['🔔','bell notification'],['🔕','no bell mute'],['🔇','mute'],['🔊','loud speaker'],
];

let _reactorTooltipBtn = null;
function _showReactorTooltip(event, btn) {
  _reactorTooltipBtn = btn;
  const reactors = JSON.parse(btn.dataset.reactors || '[]');
  const serverUrl = btn.dataset.server || CFG.own_server;
  const names = reactors.map(id => _reactorName(id, serverUrl));
  const tip = document.getElementById('reactor-tooltip');
  if (!tip) return;
  tip.textContent = names.join('\n') || '–';
  tip.hidden = false;
  const rect = btn.getBoundingClientRect();
  tip.style.left = Math.max(4, rect.left) + 'px';
  tip.style.top = (rect.top - 8) + 'px';
  tip.style.transform = 'translateY(-100%)';
  // Retry with backoff in case async lookups (registry, /node, /profile) resolve names
  const _retryReactorTooltip = (delay) => setTimeout(() => {
    if (_reactorTooltipBtn !== btn) return;
    const updated = reactors.map(id => _reactorName(id, serverUrl));
    if (updated.join('\n') !== tip.textContent) tip.textContent = updated.join('\n') || '–';
    if (delay < 8000) _retryReactorTooltip(delay * 2);
  }, delay);
  _retryReactorTooltip(800);
}
function _hideReactorTooltip() {
  _reactorTooltipBtn = null;
  const tip = document.getElementById('reactor-tooltip');
  if (tip) tip.hidden = true;
}

// ── reactors panel (long-press on +) ───────────────────────────────────────
let _longPressTimer = null;
let _longPressActivated = false;

function _reactorPhotoUrl(id, postServerUrl) {
  const { photoUrl } = _resolveIdentity(id, postServerUrl);
  if (photoUrl) return photoUrl;
  // Derive from server URL: convention is server_url + "/profile/photo"
  let base = null;
  if (!id) base = postServerUrl;
  else if (id.startsWith('http')) base = id;
  else {
    const c = (CFG?.contacts || []).find(c => (c.node_id && c.node_id === id) || (c.public_key && c.public_key === id));
    base = c?.url || serverPublicKeys[id] || null;
  }
  return base ? base.replace(/\/+$/, '') + '/profile/photo' : null;
}

function showReactorsPanel(btn) {
  document.querySelectorAll('.reactors-panel').forEach(p => p.remove());
  const bar = btn.closest('.reaction-bar');
  if (!bar) return;
  const serverUrl = bar.dataset.server || CFG?.own_server || '';
  const map = new Map();
  bar.querySelectorAll('.reaction-btn').forEach(b => {
    const emoji = b.childNodes[0]?.textContent?.trim() || '';
    JSON.parse(b.dataset.reactors || '[]').forEach(id => {
      if (!map.has(id)) { const r = _resolveIdentity(id, serverUrl); map.set(id, {...r, emojis: []}); }
      map.get(id).emojis.push(emoji);
    });
  });
  if (!map.size) return;
  const panel = document.createElement('div');
  panel.className = 'reactors-panel';
  panel.innerHTML = `<div class="reactors-panel-header"><span>Reactions</span><button class="reactors-panel-close" onclick="this.closest('.reactors-panel').remove()">✕</button></div>`;
  map.forEach(({ name, emojis }, id) => {
    const photoUrl = _reactorPhotoUrl(id, serverUrl);
    const row = document.createElement('div');
    row.className = 'reactors-panel-row';
    const initial = (name[0] || '?').toUpperCase();
    const avatarEl = document.createElement(photoUrl ? 'img' : 'div');
    if (photoUrl) {
      avatarEl.className = 'reactors-panel-avatar';
      avatarEl.src = photoUrl;
      avatarEl.alt = '';
      avatarEl.onerror = () => {
        const d = document.createElement('div');
        d.className = 'reactors-panel-initial';
        d.textContent = initial;
        avatarEl.replaceWith(d);
      };
    } else {
      avatarEl.className = 'reactors-panel-initial';
      avatarEl.textContent = initial;
    }
    const nameEl = document.createElement('span');
    nameEl.className = 'reactors-panel-name';
    nameEl.textContent = name;
    const emojiEl = document.createElement('span');
    emojiEl.className = 'reactors-panel-emojis';
    emojiEl.textContent = emojis.join(' ');
    row.append(avatarEl, nameEl, emojiEl);
    panel.appendChild(row);
  });
  document.body.appendChild(panel);
  const rect = btn.getBoundingClientRect();
  const pw = panel.offsetWidth, ph = panel.offsetHeight;
  let top = rect.bottom + 4, left = rect.left;
  if (left + pw > window.innerWidth - 8) left = window.innerWidth - pw - 8;
  if (top + ph > window.innerHeight - 8) top = rect.top - ph - 4;
  panel.style.top = Math.max(4, top) + 'px';
  panel.style.left = Math.max(4, left) + 'px';
  setTimeout(() => {
    const dismiss = e => { if (!panel.contains(e.target)) { panel.remove(); document.removeEventListener('click', dismiss, true); } };
    document.addEventListener('click', dismiss, true);
  }, 0);
}

document.addEventListener('pointerdown', e => {
  const btn = e.target.closest('.reaction-add, .reaction-btn, .reaction-btn-active');
  if (!btn) return;
  _longPressActivated = false;
  _longPressTimer = setTimeout(() => {
    _longPressActivated = true;
    _longPressTimer = null;
    showReactorsPanel(btn);
  }, 500);
});
document.addEventListener('pointerup',     () => { if (_longPressTimer) { clearTimeout(_longPressTimer); _longPressTimer = null; } });
document.addEventListener('pointercancel', () => { if (_longPressTimer) { clearTimeout(_longPressTimer); _longPressTimer = null; } });

const _normUrl = u => (u || '').replace(/\/+$/, '').toLowerCase();

function _resolveIdentity(identity, postServerUrl) {
  // null/empty → owner of the post's server
  if (!identity) {
    const url = postServerUrl || CFG.own_server;
    const prof = serverProfiles[url] || {};
    return { name: prof.display_name || prof.handle || 'Owner', photoUrl: prof.photo_url || null };
  }
  // anonymous / unauthenticated
  if (identity === '<anon>' || identity === '__anon__') {
    return { name: 'Anonymous', photoUrl: null };
  }
  // server URL identity — check profile, own-server, contacts (with URL normalization)
  if (identity.startsWith('http://') || identity.startsWith('https://')) {
    const prof = serverProfiles[identity] || {};
    if (prof.display_name || prof.handle) return { name: prof.display_name || prof.handle, photoUrl: prof.photo_url || null };
    const normId = _normUrl(identity);
    if (normId === _normUrl(CFG.own_server)) {
      const ownProf = serverProfiles[CFG.own_server] || {};
      return { name: ownProf.display_name || ownProf.handle || CFG.own_display_name || 'Me', photoUrl: ownProf.photo_url || null };
    }
    const contact = (CFG.contacts || []).find(c => _normUrl(c.url) === normId);
    if (contact) return { name: contact.name, photoUrl: prof.photo_url || null };
    const reg = _keyToProfile[identity];
    if (reg?.display_name || reg?.username) return { name: reg.display_name || ('@' + reg.username), photoUrl: null };
    _lookupKeyFromRegistry(identity);
    try { return { name: new URL(identity).hostname, photoUrl: null }; } catch { return { name: identity.slice(0, 20), photoUrl: null }; }
  }
  // node_id: own node, contacts, then registry
  if (_isNodeId(identity)) {
    if (identity === CFG?.own_node_id) {
      const ownProf = serverProfiles[CFG.own_server] || {};
      return { name: ownProf.display_name || CFG.own_display_name || 'Me', photoUrl: ownProf.photo_url || null };
    }
    const byNodeId = (CFG.contacts || []).find(c => c.node_id && c.node_id === identity);
    if (byNodeId) {
      const prof = serverProfiles[byNodeId.url] || {};
      return { name: prof.display_name || byNodeId.name, photoUrl: prof.photo_url || null };
    }
    const cached = _nodeIdToProfile[identity];
    if (cached?.display_name || cached?.handle) return { name: cached.display_name || ('@' + cached.handle), photoUrl: null };
    _lookupNodeFromRegistry(identity);
    return { name: identity.slice(0, 8), photoUrl: null };
  }
  // public key: contacts by key, registry cache, server profiles by key→url
  const byKey = (CFG.contacts || []).find(c => c.public_key && c.public_key === identity);
  if (byKey) {
    const prof = serverProfiles[byKey.url] || {};
    return { name: prof.display_name || byKey.name, photoUrl: prof.photo_url || null };
  }
  const reg = _keyToProfile[identity];
  if (reg?.display_name || reg?.username) return { name: reg.display_name || ('@' + reg.username), photoUrl: null };
  const keyUrl = serverPublicKeys[identity];
  if (keyUrl) {
    const prof = serverProfiles[keyUrl] || {};
    if (prof.display_name || prof.handle) return { name: prof.display_name || prof.handle, photoUrl: prof.photo_url || null };
    if (_normUrl(keyUrl) === _normUrl(CFG.own_server)) return { name: CFG.own_display_name || prof.handle || 'Me', photoUrl: null };
    const contact = (CFG.contacts || []).find(c => _normUrl(c.url) === _normUrl(keyUrl));
    if (contact?.name) return { name: contact.name, photoUrl: null };
    try { return { name: new URL(keyUrl).hostname, photoUrl: null }; } catch {}
  }
  _lookupKeyFromRegistry(identity);
  return { name: identity.slice(0, 8), photoUrl: null };
}

function _reactorName(identity, postServerUrl) {
  return _resolveIdentity(identity, postServerUrl).name;
}

function reactionBarHtml(reactions, postId, serverUrl) {
  const btns = (reactions || []).map(r => {
    const cls = r.reacted ? 'reaction-btn reacted' : 'reaction-btn';
    const reactorsJson = esc(JSON.stringify(r.reactors || []));
    return `<button class="${cls}" data-reactors="${reactorsJson}" data-server="${esc(serverUrl)}" onmouseenter="_showReactorTooltip(event,this)" onmouseleave="_hideReactorTooltip()" onclick="if(_longPressActivated){_longPressActivated=false;}else{event.stopPropagation();toggleReaction('${esc(postId)}','${esc(serverUrl)}','${r.emoji}',this)}">${r.emoji} <span>${r.count}</span></button>`;
  }).join('');
  const add = `<button class="reaction-add" onclick="if(_longPressActivated){_longPressActivated=false;}else{event.stopPropagation();showEmojiPicker(event,'${esc(postId)}','${esc(serverUrl)}')}" title="Add reaction • hold to see all reactions">+</button>`;
  const reply = `<button class="reaction-add" onclick="event.stopPropagation();_openReplyFromBar('${esc(postId)}')" title="Reply">↩</button>`;
  return `<div class="reaction-bar" data-post-id="${esc(postId)}" data-server="${esc(serverUrl)}">${btns}${add}${reply}</div>`;
}

function _openReplyFromBar(postId) {
  const esc = CSS.escape(postId);
  const overlay = document.getElementById('detail-overlay');
  let card = (!overlay?.hidden && overlay?.querySelector(`.post-card[data-post-id="${esc}"]`)) || null;
  if (!card) card = document.querySelector(`.post-card[data-post-id="${esc}"]`);
  if (!card) return;
  const post = allPosts.find(p => p.id === postId) || {
    id: postId,
    _server_url: card.dataset.serverUrl || CFG.own_server,
    visibility: card.dataset.visibility || 'contacts',
  };
  openReplyCompose(post, card);
}

function _trackEmojiUsed(emoji) {
  const key = 'contacc_emoji_freq';
  const freq = JSON.parse(localStorage.getItem(key) || '{}');
  freq[emoji] = (freq[emoji] || 0) + 1;
  localStorage.setItem(key, JSON.stringify(freq));
}

function _topEmoji(n = 6) {
  const freq = JSON.parse(localStorage.getItem('contacc_emoji_freq') || '{}');
  return Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, n).map(([e]) => e);
}

async function showEmojiPicker(event, postId, serverUrl) {
  const bar = event.target.closest('.reaction-bar');
  if (!bar) return;
  await _loadEmojiList();
  document.querySelectorAll('.emoji-picker').forEach(p => p.remove());
  const picker = document.createElement('div');
  picker.className = 'emoji-picker';

  // Frequently used row
  const topEmoji = _topEmoji();
  if (topEmoji.length) {
    const freqRow = document.createElement('div');
    freqRow.className = 'emoji-freq-row';
    for (const emoji of topEmoji) {
      const b = document.createElement('button');
      b.className = 'emoji-pick-btn';
      b.textContent = emoji;
      b.title = 'Recently used';
      b.onclick = e => { e.stopPropagation(); picker.remove(); _hideEmojiPreview(); _trackEmojiUsed(emoji); toggleReaction(postId, serverUrl, emoji, null); };
      freqRow.appendChild(b);
    }
    picker.appendChild(freqRow);
    const sep = document.createElement('div');
    sep.style.cssText = 'border-top:1px solid var(--border);margin:0.25rem 0';
    picker.appendChild(sep);
  }

  // Search input
  const search = document.createElement('input');
  search.type = 'text';
  search.placeholder = 'Search emoji…';
  search.className = 'emoji-search';
  search.onclick = e => e.stopPropagation();
  picker.appendChild(search);

  // Grid of emoji
  const grid = document.createElement('div');
  grid.className = 'emoji-grid';

  function renderEmoji(filter) {
    grid.innerHTML = '';
    const list = filter
      ? ALL_EMOJI.filter(([, ...kw]) => kw.some(k => k.includes(filter)) || (kw[0] || '').startsWith(filter))
      : ALL_EMOJI;
    for (const [emoji] of list.slice(0, 120)) {
      const b = document.createElement('button');
      b.className = 'emoji-pick-btn';
      b.textContent = emoji;
      b.onclick = e => { e.stopPropagation(); picker.remove(); _hideEmojiPreview(); _trackEmojiUsed(emoji); toggleReaction(postId, serverUrl, emoji, null); };
      grid.appendChild(b);
    }
  }

  renderEmoji('');
  search.oninput = () => renderEmoji(search.value.toLowerCase().trim());
  picker.appendChild(grid);

  bar.insertAdjacentElement('afterend', picker);
  setTimeout(() => search.focus(), 0);
  setTimeout(() => document.addEventListener('click', function close(e) {
    if (!picker.contains(e.target)) { picker.remove(); _hideEmojiPreview(); document.removeEventListener('click', close); }
  }), 0);
}

async function showInlineEmojiPicker(event, taId) {
  event.stopPropagation();
  const ta = document.getElementById(taId);
  if (!ta) return;
  await _loadEmojiList();
  document.querySelectorAll('.emoji-picker').forEach(p => p.remove());
  const picker = document.createElement('div');
  picker.className = 'emoji-picker';
  picker.style.cssText = 'position:fixed;z-index:1000';

  const insert = emoji => { picker.remove(); _hideEmojiPreview(); _trackEmojiUsed(emoji); _insertAtCursor(ta, emoji); ta.focus(); };

  const topEmoji = _topEmoji();
  if (topEmoji.length) {
    const freqRow = document.createElement('div');
    freqRow.className = 'emoji-freq-row';
    for (const emoji of topEmoji) {
      const b = document.createElement('button');
      b.className = 'emoji-pick-btn'; b.textContent = emoji; b.title = 'Recently used';
      b.onclick = e => { e.stopPropagation(); insert(emoji); };
      freqRow.appendChild(b);
    }
    picker.appendChild(freqRow);
    const sep = document.createElement('div');
    sep.style.cssText = 'border-top:1px solid var(--border);margin:0.25rem 0';
    picker.appendChild(sep);
  }

  const search = document.createElement('input');
  search.type = 'text'; search.placeholder = 'Search emoji…'; search.className = 'emoji-search';
  search.onclick = e => e.stopPropagation();
  picker.appendChild(search);

  const grid = document.createElement('div');
  grid.className = 'emoji-grid';
  const renderEmoji = filter => {
    grid.innerHTML = '';
    const list = filter
      ? ALL_EMOJI.filter(([, ...kw]) => kw.some(k => k.includes(filter)) || (kw[0] || '').startsWith(filter))
      : ALL_EMOJI;
    for (const [emoji] of list.slice(0, 120)) {
      const b = document.createElement('button');
      b.className = 'emoji-pick-btn'; b.textContent = emoji;
      b.onclick = e => { e.stopPropagation(); insert(emoji); };
      grid.appendChild(b);
    }
  };
  renderEmoji('');
  search.oninput = () => renderEmoji(search.value.toLowerCase().trim());
  picker.appendChild(grid);
  document.body.appendChild(picker);

  const btn = event.currentTarget || event.target.closest('button') || event.target;
  const r = btn.getBoundingClientRect();
  const pickerW = 280, pickerH = 320;
  picker.style.top = (r.bottom + window.scrollY + 4) + 'px';
  picker.style.left = Math.max(4, Math.min(r.left, window.innerWidth - pickerW - 8)) + 'px';
  if (r.bottom + pickerH + 4 > window.innerHeight) {
    picker.style.top = Math.max(4, r.top + window.scrollY - pickerH - 4) + 'px';
  }

  setTimeout(() => search.focus(), 0);
  setTimeout(() => document.addEventListener('click', function close(e) {
    if (!picker.contains(e.target)) { picker.remove(); _hideEmojiPreview(); document.removeEventListener('click', close); }
  }), 0);
}

async function toggleReaction(postId, serverUrl, emoji, _btn) {
  const params = serverUrl !== CFG.own_server ? '?server=' + encodeURIComponent(serverUrl) : '';
  const r = await apiFetch('/api/posts/' + postId + '/react' + params, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({emoji, comment_id: ''}),
  });
  if (!r.ok) {
    const status = document.getElementById('feed-status');
    if (status) { status.textContent = 'Reaction failed — try again.'; setTimeout(() => { status.textContent = ''; }, 3000); }
    return;
  }
  const data = await r.json();
  document.querySelectorAll(`.reaction-bar[data-post-id="${postId}"]`).forEach(bar => {
    const tmp = document.createElement('div');
    tmp.innerHTML = reactionBarHtml(data.reactions, postId, serverUrl);
    bar.replaceWith(tmp.firstChild);
  });
}

// ── visibility / access icons ──────────────────────────────────────────────
function _levelIcon(level) {
  if (level === 'public')        return '🌐';
  if (level === 'authenticated') return '<img src="/favicon.svg" style="width:0.85em;height:0.85em;vertical-align:middle">';
  if (level === 'contacts')      return '👥';
  if (level === 'private')       return '<svg width="11" height="11" viewBox="0 0 12 12" fill="currentColor"><path d="M0.5 1.5L11.5 1.5L7.5 6.5L7.5 10.5L4.5 10.5L4.5 6.5Z"/></svg>';
  return '';
}
function _levelIconHtml(level, title) {
  const icon = _levelIcon(level);
  if (!icon) return '';
  return `<span title="${esc(title || level)}" style="font-size:0.82rem;opacity:0.65;display:inline-flex;align-items:center;flex-shrink:0">${icon}</span>`;
}

// ── post card ──────────────────────────────────────────────────────────────
function _isPostCached(post) {
  if (post._server_url === CFG?.own_server) return false;
  return post._is_cached || serverOnline[post._server_url] === false;
}

function makePostCard(post, idx) {
  const div = document.createElement("div");
  div.className = "post-card" + (_isPostCached(post) ? " post-cached" : "");
  div.dataset.idx = idx;
  div.dataset.postId = post.id;
  div.dataset.serverUrl = post._server_url || '';
  div.dataset.visibility = post.visibility || 'contacts';

  if (post.parent_id) {
    const parentRef = document.createElement('div');
    parentRef.className = 'parent-ref';
    parentRef.innerHTML = '↩ <span class="parent-ref-text">in reply to a post</span>';
    let _parentCache = null;
    let _popoverEl = null;
    parentRef.addEventListener('mouseenter', async () => {
      if (!_parentCache) {
        const srv = await _fetchServerForNodeId(post.parent_node_id);
        const params = srv && srv !== CFG.own_server ? '?server=' + encodeURIComponent(srv) : '';
        const r = await apiFetch('/api/posts/' + post.parent_id + params);
        if (r.ok) {
          _parentCache = await r.json();
          _parentCache._server_url = _parentCache._server_url || srv || CFG.own_server;
          const label = parentRef.querySelector('.parent-ref-text');
          if (label) label.textContent = 'in reply to: ' + (_parentCache.body || '').replace(/\s+/g, ' ').slice(0, 80) + ((_parentCache.body||'').length > 80 ? '…' : '');
        }
      }
      if (_parentCache && !_popoverEl) {
        _popoverEl = document.createElement('div');
        _popoverEl.className = 'parent-popover';
        _popoverEl.textContent = (_parentCache.body || '').replace(/\s+/g, ' ').slice(0, 300) + ((_parentCache.body||'').length > 300 ? '…' : '');
        parentRef.appendChild(_popoverEl);
      }
    });
    parentRef.addEventListener('mouseleave', () => {
      if (_popoverEl) { _popoverEl.remove(); _popoverEl = null; }
    });
    parentRef.onclick = async (e) => {
      e.stopPropagation();
      const srv = _parentCache?._server_url || await _fetchServerForNodeId(post.parent_node_id);
      openPostOverlay(post.parent_id, srv, true);
    };
    div.appendChild(parentRef);
  }

  const author = document.createElement("div");
  author.className = "post-author";
  author.dataset.server = post._server_url;
  _renderAuthorInto(author, post._server_url);
  const dateFmt = fmtDate(post.created_at);
  const dateFull = fmtDateFull(post.created_at);
  const rightGroup = document.createElement("span");
  rightGroup.style.cssText = "display:inline-flex;align-items:center;gap:0.35rem;flex-shrink:0";
  rightGroup.className = "post-author-right";
  rightGroup.innerHTML = (dateFmt ? `<span class="post-date" title="${esc(dateFull)}">${dateFmt}</span>` : '')
    + _levelIconHtml(post.visibility, post.visibility)
    + `<span style="position:relative;display:inline-flex;align-items:center">`
    + `<button class="post-menu-btn" title="More options" onclick="openPostMenu(event,${idx},'${esc(post.id)}','${esc(post._server_url||'')}')">…</button>`
    + `</span>`;
  author.appendChild(rightGroup);
  div.appendChild(author);

  const bodyHtml = renderPostBody(post, {thumb: true});
  if (bodyHtml) {
    const p = document.createElement("div");
    p.className = "post-body";
    p.innerHTML = bodyHtml;
    div.appendChild(p);
  }

  const foot = document.createElement("div");
  foot.className = "post-foot";
  const tagHtml = (post.tags || []).map(t =>
    '<span class="tag-chip' + (activeTags.has(t) ? " active" : "") + '">' + esc(t) + '</span>'
  ).join("");
  if (tagHtml) {
    foot.innerHTML = tagHtml;
    div.appendChild(foot);
  }

  const rbarWrap = document.createElement('div');
  rbarWrap.innerHTML = reactionBarHtml(post.reactions || [], post.id, post._server_url);
  div.appendChild(rbarWrap.firstChild);

  const replyCount = post.reply_count || 0;
  const repliesToggle = document.createElement('div');
  repliesToggle.className = 'replies-toggle';
  repliesToggle.innerHTML = '<span style="display:inline-flex;align-items:center;gap:0.35rem">'
    + '<span class="replies-toggle-arrow">▶</span>'
    + '<span class="replies-toggle-label">' + replyCount + ' repl' + (replyCount !== 1 ? 'ies' : 'y') + '</span>'
    + '</span>';
  repliesToggle.onclick = () => _toggleReplies(post, div);
  repliesToggle.hidden = (replyCount === 0);
  div.appendChild(repliesToggle);

  const repliesPanel = document.createElement('div');
  repliesPanel.className = 'replies-panel';
  repliesPanel.dataset.postId = post.id;
  repliesPanel.hidden = true;
  div.appendChild(repliesPanel);

  const replyPanel = document.createElement("div");
  replyPanel.className = "reply-panel";
  replyPanel.dataset.postId = post.id;
  replyPanel.hidden = true;
  div.appendChild(replyPanel);

  return div;
}

// ── keyboard nav ───────────────────────────────────────────────────────────
document.addEventListener("keydown", e => {
  if (e.key === "Escape") closeAllPostMenus();
  if (!document.getElementById("detail-overlay").hidden && e.key === "Escape") closeDetail();
  if (!document.getElementById("lightbox").hidden && e.key === "Escape") closeLightbox();
  if (!document.getElementById("compose-overlay").hidden && e.key === "Escape") closeCompose();
  if (!document.getElementById("edit-overlay").hidden && e.key === "Escape") closeEdit();
  if (!document.getElementById("profile-overlay").hidden && e.key === "Escape") closeProfile();
  if (!document.getElementById("add-contact-overlay").hidden && e.key === "Escape") closeAddContact();
  if (!document.getElementById("contact-edit-overlay").hidden && e.key === "Escape") closeContactEdit();
});

// Configure marked once: GFM + line breaks + Discord-style -# small text
marked.use({ gfm: true, breaks: true });
marked.use({
  extensions: [{
    name: 'small',
    level: 'block',
    start(src) { return src.indexOf('-# '); },
    tokenizer(src) {
      const match = src.match(/^-# ([^\n]*)/);
      if (match) return { type: 'small', raw: match[0], text: match[1].trim() };
    },
    renderer(token) {
      return `<small>${marked.parseInline(token.text)}</small>`;
    },
  }],
});

function mdRender(text) {
  return DOMPurify.sanitize(marked.parse(text), {
    ALLOWED_TAGS: ['p','br','strong','em','del','code','pre','blockquote',
                   'h1','h2','h3','h4','h5','h6','ul','ol','li','hr',
                   'a','img','table','thead','tbody','tr','th','td',
                   'span','div','small'],
    ALLOWED_ATTR: ['href','src','alt','title','class','target','data-mention-id'],
    ALLOW_DATA_ATTR: false,
  });
}

// Render a plain text body with markdown + mention substitution (no assets).
function renderBodyText(text) {
  // Protect [id|display] mention tokens from markdown by substituting placeholders.
  const phMap = new Map();
  let pi = 0;
  const withPh = text.replace(/\[([^|\]]+)\|([^\]]+)\]/g, (_, id, disptext) => {
    const ph = `CCPH${pi++}END`;
    const _name = disptext || _resolveIdentity(id, '').name;
    phMap.set(ph, `<span class="mention-tag" data-mention-id="${esc(id)}" onmouseenter="_showMentionPopup(event,this)" onmouseleave="_hideMentionPopup(event)">${esc(_name)}</span>`);
    return ph;
  });
  let html = mdRender(withPh);
  for (const [ph, mentionHtml] of phMap) html = html.split(ph).join(mentionHtml);
  return html;
}

function renderPostBody(post, opts = {}) {
  const assetMap = {};
  for (const a of (post.assets || [])) assetMap[a.id] = a;

  // Split on asset tokens, render each text segment as markdown+mentions,
  // interleave with asset HTML.
  const parts = (post.body || "").split(/(\[asset:[0-9a-f-]+\])/);
  let rendered = "";
  for (const part of parts) {
    const m = part.match(/^\[asset:([0-9a-f-]+)\]$/);
    if (m) {
      const aid = m[1], a = assetMap[aid];
      const params = post._server_url !== CFG.own_server
        ? "?server=" + encodeURIComponent(post._server_url) : "";
      const fullBase = "/api/assets/" + aid + params + clientTokenParam(!!params);
      const fullSrc = fullBase + (a?.content_hash ? (fullBase.includes('?') ? '&' : '?') + 'hash=' + encodeURIComponent(a.content_hash) : '');
      if (a && (a.media_type || "").startsWith("image/")) {
        if (opts.thumb) {
          const thumbBase = "/api/assets/" + aid + "/thumb" + params + clientTokenParam(!!params);
          const hashQ = a.content_hash ? (thumbBase.includes('?') ? '&' : '?') + 'hash=' + encodeURIComponent(a.content_hash) : '';
          const thumbSrc = thumbBase + hashQ + (hashQ ? '&' : '?') + 'tq=640';
          rendered += '<span class="asset-block"><img src="' + thumbSrc + '" alt="" loading="lazy" class="post-thumb loading"'
            + ' data-full="' + esc(fullSrc) + '"'
            + ' onload="this.classList.remove(\'loading\')" onerror="this.classList.remove(\'loading\')"'
            + ' onclick="openLightbox(this.dataset.full)"></span>';
        } else {
          rendered += '<span class="asset-block"><img src="' + fullSrc + '" alt="" onclick="openLightbox(this.src)"></span>';
        }
      } else if (a && (a.media_type || "").startsWith("video/"))
        rendered += '<span class="asset-block"><video src="' + fullSrc + '" controls></video></span>';
      else {
        const label = (a && a.title) ? a.title : aid.slice(0, 8) + "…";
        rendered += '<span class="asset-block"><a class="asset-file" href="' + fullSrc + '" download>' + mimeIcon(a && a.media_type) + ' ' + esc(label) + '</a></span>';
      }
    } else {
      rendered += renderBodyText(part);
    }
  }
  return rendered;
}

// ── polling / SSE ──────────────────────────────────────────────────────────
const POLL_DETAIL_MS    = 120_000; // fallback poll for open panels (SSE covers live updates)
const BG_CHECK_MS       = 60_000;   // how often the scheduler wakes to check due servers
const DEFAULT_POLL_MS   = 30 * 60_000;
const MIN_POLL_MS       =  5 * 60_000;
const MAX_POLL_MS       = 60 * 60_000;
let _serverActivity7d = {};  // url → 7-day activity count from last /node probe

let _detailPollTimer  = null;
let _bgFetchTimer     = null;
let _serverLastFetched  = {};     // url → ms timestamp of last successful fetch
let _serverPollIntervals = {};    // url → ms (computed from node activity)
const _openPanels = new Map();    // postId → post
let _newestKnownAt = 0;           // created_at of newest post we've ever seen; survives allPosts = []

let _sseSource = null;  // active EventSource, or null

function _computePollInterval(activity7d, poll_weight) {
  const weight = Math.max(0.1, poll_weight ?? 0.5);
  const base = activity7d
    ? Math.max(MIN_POLL_MS, Math.min(MAX_POLL_MS, Math.round(30 * 60_000 / (activity7d / 7))))
    : MAX_POLL_MS;
  return Math.max(MIN_POLL_MS, Math.min(MAX_POLL_MS, Math.round(base / weight)));
}

function _sseToken() { return getClientToken() || ''; }

function _openSSE() {
  if (_sseSource) return;
  const token = _sseToken();
  if (!token) return;
  _sseSource = new EventSource(`/api/events?client_token=${encodeURIComponent(token)}`);
  _sseSource.onmessage = (e) => {
    try { _handleSSEEvent(JSON.parse(e.data)); } catch (_) {}
  };
  _sseSource.onerror = () => {
    _sseSource.close();
    _sseSource = null;
    if (document.visibilityState === 'visible') setTimeout(_openSSE, 5000);
  };
}

function _closeSSE() {
  if (_sseSource) { _sseSource.close(); _sseSource = null; }
}

function _handleSSEEvent(upd) {
  if (upd.type === 'dm') {
    if (upd.event === 'member_names_resolved') {
      _loadDmThreads().then(() => _renderDmMessages());
      return;
    }
    if (_dmActiveThread && upd.thread_id === _dmActiveThread) {
      _loadDmMessages(_dmActiveThread);
      apiFetch("/api/dm/threads/" + _dmActiveThread + "/seen", {method: "POST"})
        .then(() => _loadDmThreads());
    } else {
      _loadDmThreads();
    }
    return;
  }
  if (_openPanels.size === 0) return;
  const post = _openPanels.get(upd.post_id);
  if (!post) return;
  if (upd.event === 'reaction') {
    const reactions = upd.data?.reactions;
    if (reactions) {
      const serverUrl = post._server_url || CFG.own_server;
      document.querySelectorAll(`.reaction-bar[data-post-id="${upd.post_id}"]`).forEach(bar => {
        const tmp = document.createElement('div');
        tmp.innerHTML = reactionBarHtml(reactions, upd.post_id, serverUrl);
        bar.replaceWith(tmp.firstChild);
      });
    }
  }
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    _openSSE();
  } else {
    _closeSSE();
  }
});

function _startDetailPoll() {
  clearInterval(_detailPollTimer);
  if (_openPanels.size === 0) return;
  _detailPollTimer = setInterval(_pollOpenPanels, POLL_DETAIL_MS);
  _openSSE();
}
function _stopDetailPoll() {
  const dmPanel = document.getElementById("dm-panel");
  if (dmPanel && !dmPanel.hidden) return;
  clearInterval(_detailPollTimer); _detailPollTimer = null;
}
// _applySubscribedUpdates removed — replaced by SSE (_handleSSEEvent)

function _startBgFetch() {
  clearInterval(_bgFetchTimer);
  _bgFetchTimer = setInterval(_runBgFetch, BG_CHECK_MS);
}

// ── localStorage feed cache ────────────────────────────────────────────────
function _cacheKey() { return 'feedv5:' + (CFG?.own_server || ''); }
function _saveFeedCache(posts) {
  try { localStorage.setItem(_cacheKey(), JSON.stringify({ ts: Date.now(), posts: posts.slice(0, 100) })); } catch(e) {}
}
function _loadFeedCache() {
  try { return JSON.parse(localStorage.getItem(_cacheKey()) || 'null'); } catch(e) { return null; }
}

async function _pollOpenPanels() {
  if (document.hidden) return;
  for (const [postId, post] of _openPanels) {
    const params = post._server_url !== CFG.own_server ? '?server=' + encodeURIComponent(post._server_url) : '';
    const r = await apiFetch('/api/posts/' + postId + params);
    if (!r.ok) continue;
    const updated = await r.json();
    if (!updated.reactions) continue;
    post.reactions = updated.reactions;
    document.querySelectorAll(`.reaction-bar[data-post-id="${postId}"]`).forEach(bar => {
      const tmp = document.createElement('div');
      tmp.innerHTML = reactionBarHtml(updated.reactions, postId, post._server_url);
      bar.replaceWith(tmp.firstChild);
    });
  }
}

// Apply a fresh batch of posts from one server to the visible feed.
function _applyFreshPosts(freshPosts) {
  const newestTs = Math.max(_newestKnownAt, allPosts[0]?.created_at || 0);
  let newCount = 0;
  const byId = new Map(freshPosts.map(p => [p.id, p]));

  document.querySelectorAll('.post-card[data-post-id]').forEach(card => {
    const updated = byId.get(card.dataset.postId);
    if (!updated) return;
    const post = allPosts.find(p => p.id === updated.id);
    if (post) { post.reactions = updated.reactions; post.body = updated.body; }
    if (updated.reactions) {
      const serverUrl = post?._server_url || CFG.own_server;
      card.querySelectorAll(`.reaction-bar[data-post-id="${updated.id}"]`).forEach(bar => {
        const tmp = document.createElement('div');
        tmp.innerHTML = reactionBarHtml(updated.reactions, updated.id, serverUrl);
        bar.replaceWith(tmp.firstChild);
      });
    }
    // drop the stale marker now that fresh data has arrived
    card.classList.remove('post-stale');
  });

  document.querySelectorAll('.post-card[data-post-id]').forEach(card => {
    const post = allPosts.find(p => p.id === card.dataset.postId);
    if (post) card.classList.toggle('post-cached', _isPostCached(post));
  });

  if (freshPosts.length > 0) _newestKnownAt = Math.max(_newestKnownAt, freshPosts[0].created_at || 0);
  const existingIds = new Set(allPosts.map(p => p.id));
  const newPosts = freshPosts
    .filter(p => p.created_at > newestTs && !existingIds.has(p.id))
    .sort((a, b) => (a.created_at || 0) - (b.created_at || 0));
  for (const p of newPosts) prependPost(p);
}

// Merge fresh posts from one server into the global cache on disk.
function _mergeCachePosts(serverUrl, freshPosts) {
  const cached = _loadFeedCache();
  const freshIds = new Set(freshPosts.map(p => p.id));
  const existing = (cached?.posts || []).filter(p => p._server_url !== serverUrl && !freshIds.has(p.id));
  const merged = [...freshPosts, ...existing]
    .sort((a, b) => (b.created_at || 0) - (a.created_at || 0))
    .slice(0, 100);
  _saveFeedCache(merged);
}

// Fetch one server, update cache, update visible feed if on feed view.
async function _fetchOneServer(url) {
  try {
    const params = url !== CFG.own_server ? '?server=' + encodeURIComponent(url) : '';
    const r = await apiFetch('/api/feed?limit=50' + (params ? '&' + params.slice(1) : ''));
    if (!r.ok) { serverOnline[url] = false; renderServerList(); return; }
    const d = await r.json();
    serverOnline[url] = true;
    if (d.server_status) {
      for (const [u, st] of Object.entries(d.server_status)) serverOnline[u] = st === 'online';
    }
    const posts = d.posts || [];
    _serverLastFetched[url] = Date.now();
    _mergeCachePosts(url, posts);
    if (!document.getElementById('feed-view').hidden) _applyFreshPosts(posts);
    renderServerList();
  } catch { serverOnline[url] = false; renderServerList(); }
}

// Background scheduler: wakes every minute, fetches servers that are due.
async function _runBgFetch() {
  loadMentions();
  const now = Date.now();
  const servers = activeServer ? [activeServer] : [CFG.own_server, ...(CFG.contacts || []).map(c => c.url)];
  await Promise.all(servers.map(async url => {
    const interval = _serverPollIntervals[url] || DEFAULT_POLL_MS;
    if (now - (_serverLastFetched[url] || 0) >= interval) await _fetchOneServer(url);
  }));
}



async function _toggleReplies(post, cardEl) {
  const panel = cardEl.querySelector('.replies-panel');
  const toggle = cardEl.querySelector('.replies-toggle');
  const arrow = toggle?.querySelector('.replies-toggle-arrow');
  if (!panel) return;
  if (!panel.hidden) {
    panel.hidden = true;
    if (arrow) arrow.textContent = '▶';
    return;
  }
  if (arrow) arrow.textContent = '▼';
  panel.innerHTML = '<div style="color:var(--text-5);font-size:0.82rem;padding:0.5rem 0">Loading replies…</div>';
  panel.hidden = false;

  const params = post._server_url && post._server_url !== CFG.own_server
    ? '?server=' + encodeURIComponent(post._server_url) : '';
  const r = await apiFetch('/api/posts/' + post.id + '/replies' + params);
  if (!r.ok) { panel.innerHTML = ''; return; }
  const refs = (await r.json()).replies || [];

  if (refs.length === 0) {
    panel.innerHTML = '<div style="color:var(--text-5);font-size:0.82rem;padding:0.5rem 0">No replies yet.</div>';
    return;
  }

  const fetched = await Promise.all(refs.map(async ref => {
    const srv = await _fetchServerForNodeId(ref.reply_node_id);
    const p = srv && srv !== CFG.own_server ? '?server=' + encodeURIComponent(srv) : '';
    try {
      const rr = await apiFetch('/api/posts/' + ref.reply_post_id + p);
      if (!rr.ok) return null;
      const rp = await rr.json();
      rp._server_url = rp._server_url || srv || CFG.own_server;
      return rp;
    } catch { return null; }
  }));

  const sorted = fetched.filter(Boolean).sort((a, b) => a.created_at - b.created_at);
  panel.innerHTML = '';
  for (const rp of sorted) {
    const card = makePostCard(rp, -1);
    card.style.cssText = 'margin-top:0.5rem;border-left:2px solid var(--border-strong);padding-left:0.75rem;cursor:pointer';
    card.addEventListener('click', e => {
      if (e.target.closest('button, a, input, textarea, .reply-panel, .replies-toggle')) return;
      const nestedReplies = card.querySelector('.replies-panel');
      if (nestedReplies && nestedReplies.contains(e.target)) return;
      openPostOverlay(rp.id, rp._server_url);
    });
    panel.appendChild(card);
  }
}

// ── reply compose ──────────────────────────────────────────────────────────
function _nodeIdForServer(serverUrl) {
  const norm = u => (u || '').replace(/\/+$/, '');
  if (norm(serverUrl) === norm(CFG?.own_server)) return CFG?.own_node_id || '';
  const contact = (CFG?.contacts || []).find(c => norm(c.url) === norm(serverUrl));
  return contact?.node_id || '';
}

function _serverForNodeId(nodeId) {
  if (!nodeId) return '';
  if (nodeId === CFG?.own_node_id) return CFG?.own_server || '';
  const contact = (CFG?.contacts || []).find(c => c.node_id === nodeId);
  return contact?.url || '';
}

async function _fetchServerForNodeId(nodeId) {
  const url = _serverForNodeId(nodeId);
  if (url) return url;
  try {
    const r = await apiFetch('/api/registry/node/' + encodeURIComponent(nodeId));
    if (r.ok) return (await r.json()).server_url || '';
  } catch {}
  return '';
}

async function openPostOverlay(postId, serverUrl, expandReplies = false) {
  const params = serverUrl && serverUrl !== CFG.own_server ? '?server=' + encodeURIComponent(serverUrl) : '';
  const r = await apiFetch('/api/posts/' + postId + params);
  if (!r.ok) return;
  const post = await r.json();
  post._server_url = post._server_url || serverUrl || CFG.own_server;
  const body = document.getElementById('detail-body');
  body.innerHTML = '';
  const card = makePostCard(post, -1);
  body.appendChild(card);
  document.getElementById('nav-prev').hidden = true;
  document.getElementById('nav-next').hidden = true;
  document.getElementById('detail-overlay').hidden = false;
  if (expandReplies) _toggleReplies(post, card);
}

function closeDetail() {
  document.getElementById('detail-overlay').hidden = true;
}

function openReplyCompose(post, cardEl) {
  const panel = cardEl.querySelector('.reply-panel');
  if (!panel) return;
  if (!panel.hidden) { panel.hidden = true; return; }

  const taId = 'reply-ta-' + post.id;
  const cbId = 'reply-notify-' + post.id;
  panel.innerHTML =
    `<div style="margin-top:0.5rem">`
    + `<textarea id="${esc(taId)}" class="reply-input" data-post-id="${esc(post.id)}" placeholder="Write a reply…" style="width:100%;box-sizing:border-box;display:block"></textarea>`
    + `<div style="display:flex;align-items:center;gap:0.35rem;margin-top:0.3rem;flex-wrap:wrap">`
    + `<button class="reaction-add" onclick="showInlineEmojiPicker(event,'${esc(taId)}')" title="Insert emoji">😊</button>`
    + `<button class="reaction-add" onclick="openComposeAsReply('${esc(post.id)}','${esc(post._server_url||'')}',document.getElementById('${esc(taId)}'))" title="Full compose panel">⊞</button>`
    + `<button class="reaction-add" onclick="openPostOverlay('${esc(post.id)}','${esc(post._server_url||'')}')" title="View post">⤢</button>`
    + `<label style="display:inline-flex;align-items:center;gap:0.3rem;font-size:0.82rem;color:#aaa;cursor:pointer">`
    + `<input type="checkbox" id="${esc(cbId)}" checked> List in parent's replies</label>`
    + `<span style="flex:1"></span>`
    + `<button class="btn btn-primary btn-sm" onclick="submitReply(event,'${esc(post.id)}','${esc(post._server_url||'')}','${esc(post.visibility||'contacts')}')">Post reply</button>`
    + `<button class="btn btn-muted btn-sm" onclick="this.closest('.reply-panel').hidden=true">Cancel</button>`
    + `<span class="reply-error" style="color:#e06c6c;font-size:0.82rem"></span>`
    + `</div>`
    + `<div class="reply-list"></div>`
    + `</div>`;

  panel.hidden = false;
  panel.scrollIntoView({block: 'nearest', behavior: 'smooth'});
  document.getElementById(taId)?.focus();
}

async function submitReply(e, parentPostId, parentServerUrl, visibility) {
  e.stopPropagation();
  const panel = document.querySelector(`.reply-panel[data-post-id="${parentPostId}"]`);
  if (!panel) return;
  const ta = panel.querySelector('.reply-input');
  const err = panel.querySelector('.reply-error');
  const btn = panel.querySelector('.btn-primary');
  const notifyCheck = panel.querySelector('input[type="checkbox"]');
  const bodyText = ta?.value?.trim();
  if (!bodyText) return;

  btn.disabled = true;
  if (err) err.textContent = '';

  const parentNodeId = _nodeIdForServer(parentServerUrl);
  const fd = new FormData();
  fd.append('body', _expandMentions(bodyText));
  fd.append('visibility', visibility);
  fd.append('parent_id', parentPostId);
  if (parentNodeId) fd.append('parent_node_id', parentNodeId);
  if (parentServerUrl && parentServerUrl !== CFG?.own_server) fd.append('parent_server_url', parentServerUrl);

  const postUrl = '/api/posts' + (notifyCheck?.checked ? '?notify_parent=1' : '');
  try {
    const r = await apiFetch(postUrl, {method: 'POST', body: fd});
    if (r.ok) {
      const reply = await r.json();
      ta.value = '';

      const cardEl = panel.parentElement;
      const repliesToggle = cardEl?.querySelector('.replies-toggle');
      const label = repliesToggle?.querySelector('.replies-toggle-label');
      if (label) {
        const n = (parseInt(label.textContent) || 0) + 1;
        label.textContent = n + ' repl' + (n !== 1 ? 'ies' : 'y');
      }
      if (repliesToggle) repliesToggle.hidden = false;
      panel.hidden = true;
      // Open (or refresh) the replies panel so the user sees the new reply
      if (cardEl) {
        const repliesPanel = cardEl.querySelector('.replies-panel');
        if (repliesPanel && !repliesPanel.hidden) repliesPanel.hidden = true;
        const postRef = { id: parentPostId, _server_url: parentServerUrl || CFG?.own_server };
        _toggleReplies(postRef, cardEl);
      }
    } else {
      if (err) err.textContent = 'Error ' + r.status;
      btn.disabled = false;
    }
  } catch {
    if (err) err.textContent = 'Network error';
    btn.disabled = false;
  }
}

// ── @mention autocomplete ──────────────────────────────────────────────────
let _mentionState = null;
const COMPOSE_CTX = { taId: 'compose-body', hlId: 'compose-highlight', ddId: 'compose-mention-dropdown' };
const EDIT_CTX    = { taId: 'edit-body',    hlId: 'edit-highlight',    ddId: 'edit-mention-dropdown' };
let _mentionCtx = COMPOSE_CTX;
// Tracks mentions selected from the dropdown this session: [{lowerLabel, contact}]
// Enables resolving edited tags (e.g. @Jon → @Jonathan) back to the right contact.
let _sessionMentionEntries = [];
// Tracks a mention actively being edited after dropdown selection: {atPos, contact}
// atPos is the index of the '@' in the textarea value.
let _activeMentionEdit = null;

function _contactTag(c) {
  const displayName = (serverProfiles[c.url] || {}).display_name || c.name;
  return c.tag || displayName.trim().split(/\s+/)[0] || c.handle || 'contact';
}

function _mentionTag(c) {
  return '@' + _contactTag(c);
}

async function _saveContactTag(contact, newTag) {
  if (!contact?.url || !newTag) return;
  const current = (CFG?.contacts || []).find(c => c.url === contact.url);
  if (current?.tag === newTag) return;
  try {
    const r = await apiFetch('/api/contacts', {
      method: 'PATCH', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: contact.url, tag: newTag}),
    });
    if (r.ok) { const cfg = await (await apiFetch('/api/config')).json(); _setCFG(cfg); _updateHighlight(); }
  } catch (e) {}
}

// Expand @tag → [pubkey|tag] for known contacts. Called at submit time.
function _expandMentions(text) {
  const tagMap = new Map();
  for (const c of (CFG?.contacts || [])) {
    const id = c.node_id || (serverProfiles[c.url] || {}).owner_id || c.public_key;
    if (!id) continue;
    const tag = _contactTag(c);
    tagMap.set(tag.toLowerCase(), {label: tag, id, contact: c});
  }
  const toSave = [];
  const result = text.replace(/@\[([^\]]*)\]|@(\w+)/g, (full, bracketContent, word) => {
    const inner = (bracketContent !== undefined ? bracketContent : word).trim();
    if (!inner) return full;
    const lower = inner.toLowerCase();
    // 1. Exact match on saved tag
    const entry = tagMap.get(lower);
    if (entry) return `[${entry.id}|${inner}]`;
    // 2. Prefix match against known tags or session entries (user extended the label inline)
    let best = null;
    for (const [tag, entry] of tagMap) {
      if (lower.startsWith(tag) && tag.length >= 2) {
        if (!best || tag.length > best.lowerLabel.length)
          best = {lowerLabel: tag, contact: entry.contact};
      }
    }
    for (const e of _sessionMentionEntries) {
      if (lower.startsWith(e.lowerLabel) && e.lowerLabel.length >= 2) {
        if (!best || e.lowerLabel.length > best.lowerLabel.length) best = e;
      }
    }
    if (best) {
      const id = best.contact.node_id || (serverProfiles[best.contact.url] || {}).owner_id || best.contact.public_key;
      if (id) {
        if (inner !== _contactTag(best.contact)) toSave.push({contact: best.contact, newTag: inner});
        return `[${id}|${inner}]`;
      }
    }
    return full;
  });
  for (const {contact, newTag} of toSave) _saveContactTag(contact, newTag);
  return result;
}

// Collapse [pubkey|disptext] → @tag (reader's current tag for that pubkey). Called when loading for edit.
function _collapseMentions(text) {
  return text.replace(/\[([^|\]]+)\|([^\]]+)\]/g, (full, id, disptext) => {
    const contact = (CFG?.contacts || []).find(c => c.node_id === id || c.public_key === id);
    const tag = contact ? _contactTag(contact) : disptext;
    return /\s/.test(tag) ? `@[${tag}]` : `@${tag}`;
  });
}

// Render [pubkey|disptext] tokens in a post body as styled mention spans.
// Uses the stored disptext as the label; tooltip shows the contact's display name.
function _renderMentions(text) {
  return text.split(/(\[[^\]]+\])/).map(part => {
    const m = part.match(/^\[([^|\]]+)\|([^\]]+)\]$/);
    if (!m) return esc(part);
    const id = m[1], disptext = m[2];
    const _n = disptext || _resolveIdentity(id, '').name;
    return `<span class="mention-tag" data-mention-id="${esc(id)}" onmouseenter="_showMentionPopup(event,this)" onmouseleave="_hideMentionPopup(event)">${esc(_n)}</span>`;
  }).join('');
}

// Commit an in-progress mention edit: save the new tag and add to session entries.
function _commitActiveMentionEdit() {
  if (!_activeMentionEdit) return;
  const { atPos, contact } = _activeMentionEdit;
  _activeMentionEdit = null;
  const ta = document.getElementById(_mentionCtx.taId);
  if (!ta) return;
  const text = ta.value;
  if (atPos >= text.length || text[atPos] !== '@') return;
  const m = text.slice(atPos).match(/^@\[([^\]]*)\]|^@(\w+)/);
  if (!m) return;
  const word = (m[1] !== undefined ? m[1] : m[2]).trim();
  if (!word) return;
  const currentTag = _contactTag(contact);
  if (word.toLowerCase() !== currentTag.toLowerCase()) {
    _sessionMentionEntries.push({ lowerLabel: word.toLowerCase(), contact });
    _saveContactTag(contact, word);
  }
}

function onComposeInput() {
  // If the cursor has left the @word being edited, commit the tag change.
  if (_activeMentionEdit) {
    const ta = document.getElementById(_mentionCtx.taId);
    const pos = ta.selectionStart;
    const text = ta.value;
    const { atPos } = _activeMentionEdit;
    let still = false;
    if (atPos < text.length && text[atPos] === '@') {
      const m = text.slice(atPos).match(/^@\[([^\]]*)\]|^@(\w*)/);
      if (m) {
        // For bracket form, cursor must be before the closing ]
        const end = atPos + m[0].length;
        const max = m[1] !== undefined ? end - 1 : end;
        if (pos >= atPos && pos <= max) still = true;
      }
    }
    if (!still) _commitActiveMentionEdit();
  }
  _updateHighlight();
  const ta = document.getElementById(_mentionCtx.taId);
  const pos = ta.selectionStart;
  const before = ta.value.substring(0, pos);
  // @[... means cursor is inside a bracket mention — no dropdown while freely typing
  const bracketMatch = before.match(/@\[([^\]]*)$/);
  if (bracketMatch) { hideMentionDropdown(); return; }
  const match = before.match(/@(\w*)$/);
  if (!match) { hideMentionDropdown(); return; }
  const query = match[1].toLowerCase();
  const _words = s => s.toLowerCase().split(/\s+/);
  const _starts = (s, q) => q === '' || s.toLowerCase().startsWith(q) || _words(s).some(w => w.startsWith(q));
  const contacts = (CFG?.contacts || []).filter(c => {
    const prof = serverProfiles[c.url] || {};
    return _starts(c.tag || '', query)
        || _starts(c.name, query)
        || _starts(c.handle || '', query)
        || _starts(prof.display_name || '', query)
        || _starts(prof.handle || '', query);
  });
  if (!contacts.length) { hideMentionDropdown(); return; }
  _mentionState = { start: pos - match[0].length, query, focused: 0, contacts };
  const dd = document.getElementById(_mentionCtx.ddId);
  if (!dd) return;
  dd.innerHTML = '';
  contacts.forEach((c, i) => {
    const prof = serverProfiles[c.url] || {};
    const displayName = prof.display_name || c.name;
    const tagLabel = _contactTag(c);
    const el = document.createElement('div');
    el.className = 'mention-item' + (i === 0 ? ' focused' : '');
    el.innerHTML = `<span class="mention-item-name">${esc(displayName)}</span><span class="mention-item-handle">@${esc(tagLabel)}</span>`;
    el.onmousedown = e => { e.preventDefault(); _selectMention(c); };
    dd.appendChild(el);
  });
  dd.hidden = false;
}

function hideMentionDropdown() {
  const dd = document.getElementById(_mentionCtx.ddId);
  if (dd) dd.hidden = true;
  _mentionState = null;
}

function _selectMention(c) {
  const state = _mentionState;
  if (!state) return;
  const ta = document.getElementById(_mentionCtx.taId);
  const label = _contactTag(c);
  const replacement = `@${label} `;
  const before = ta.value.substring(0, state.start);
  // Use the known end of "@query" from state rather than ta.selectionStart,
  // which can be wrong if focus shifted momentarily during the click.
  const mentionEnd = state.start + 1 + state.query.length;
  const after = ta.value.substring(mentionEnd);
  ta.value = before + replacement + after;
  const p = before.length + replacement.length;
  ta.selectionStart = ta.selectionEnd = p;
  _sessionMentionEntries.push({lowerLabel: label.toLowerCase(), contact: c});
  _activeMentionEdit = { atPos: before.length, contact: c };
  hideMentionDropdown();
  _updateHighlight();
  ta.focus();
}

function onComposeKeydown(e) {
  if (!_mentionState) return;
  const _dd = document.getElementById(_mentionCtx.ddId);
  if (!_dd) return;
  const items = _dd.querySelectorAll('.mention-item');
  if (!items.length) return;
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    _mentionState.focused = Math.min(_mentionState.focused + 1, items.length - 1);
    items.forEach((el, i) => el.classList.toggle('focused', i === _mentionState.focused));
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    _mentionState.focused = Math.max(_mentionState.focused - 1, 0);
    items.forEach((el, i) => el.classList.toggle('focused', i === _mentionState.focused));
  } else if (e.key === 'Enter' || e.key === 'Tab') {
    const c = _mentionState.contacts[_mentionState.focused];
    if (c) { e.preventDefault(); _selectMention(c); }
  } else if (e.key === 'Escape') {
    e.preventDefault();  // prevent compose modal from closing while dropdown is open
    hideMentionDropdown();
  }
}

function _updateHighlight() {
  const ta = document.getElementById(_mentionCtx.taId);
  if (!ta) return;
  const hl = _mentionCtx.hlId ? document.getElementById(_mentionCtx.hlId) : null;
  if (_mentionCtx.hlId && !hl) return;
  const knownTags = new Set(
    (CFG?.contacts || []).map(c => _contactTag(c).toLowerCase())
  );
  const _e = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const text = ta.value;
  let html = '';
  let last = 0;
  // Matches @[text with spaces] or @word
  const re = /@\[([^\]]*)\]|@(\w+)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const atPos = m.index;
    const isBracket = m[1] !== undefined;
    const inner = isBracket ? m[1] : m[2];
    const lower = inner.toLowerCase().trim();
    html += _e(text.slice(last, atPos));
    const lit = (() => {
      if (knownTags.has(lower)) return true;
      // Keep highlight while user edits (bidirectional prefix — word growing or shrinking)
      for (const tag of knownTags)
        if (tag.length >= 2 && lower.length >= 2 && (lower.startsWith(tag) || tag.startsWith(lower))) return true;
      for (const e of _sessionMentionEntries) {
        const el = e.lowerLabel;
        if (el.length >= 2 && lower.length >= 2 && (lower.startsWith(el) || el.startsWith(lower))) return true;
      }
      // Keep highlight for the mention the user is actively rewriting after a dropdown pick
      if (_activeMentionEdit?.atPos === atPos) return true;
      return false;
    })();
    if (lit) {
      html += isBracket
        ? `<span class="mention-bracket">@[</span><span class="mention-tag">${_e(inner)}</span><span class="mention-bracket">]</span>`
        : `<span class="mention-tag">@${_e(inner)}</span>`;
    } else {
      html += _e(m[0]);
    }
    last = atPos + m[0].length;
  }
  html += _e(text.slice(last));
  if (hl) { hl.innerHTML = html + '​'; hl.scrollTop = ta.scrollTop; }
}

// ── compose ────────────────────────────────────────────────────────────────
function composeShowTab(tab) {
  const isPreview = tab === 'preview';
  document.getElementById("compose-body-wrap").hidden = isPreview;
  document.getElementById("compose-preview-wrap").hidden = !isPreview;
  document.getElementById("compose-tab-write").style.cssText =
    "background:none;border:none;border-bottom:2px solid " + (isPreview ? "transparent" : "var(--accent)") + ";color:" + (isPreview ? "var(--text-4)" : "var(--text-1)") + ";padding:0.3rem 0.75rem;cursor:pointer;font-size:0.85rem";
  document.getElementById("compose-tab-preview").style.cssText =
    "background:none;border:none;border-bottom:2px solid " + (isPreview ? "var(--accent)" : "transparent") + ";color:" + (isPreview ? "var(--text-1)" : "var(--text-4)") + ";padding:0.3rem 0.75rem;cursor:pointer;font-size:0.85rem";
  if (isPreview) {
    const body = document.getElementById("compose-body").value;
    const previewPost = {
      body,
      assets: _uploadedAssets.filter(a => a.id).map(a => ({id: a.id, media_type: a.media_type, title: a.title})),
      _server_url: CFG?.own_server,
    };
    document.getElementById("compose-preview-wrap").innerHTML = renderPostBody(previewPost) || '<em style="color:#555">Nothing to preview.</em>';
  } else {
    document.getElementById("compose-body").focus();
  }
}

// When space is pressed inside an active plain @word mention, convert to @[word ] form
// so the user can keep typing a label that contains spaces.
// When space is pressed inside (or just after) an active @word mention, convert
// to @[word ] so the user can keep typing a label that contains spaces.
function _handleMentionSpaceKey(e) {
  if (e.key !== ' ' || !_activeMentionEdit) return false;
  const ta = document.getElementById(_mentionCtx.taId);
  if (!ta) return false;
  const { atPos } = _activeMentionEdit;
  const text = ta.value;
  const m = text.slice(atPos).match(/^@(\w+)/);
  if (!m) return false; // already bracket form or no plain word
  const word = m[1];
  const wordEnd = atPos + m[0].length;
  const pos = ta.selectionStart;
  // Also allow cursor at wordEnd+1 when that char is the trailing space _selectMention added,
  // so pressing space immediately after a dropdown pick still triggers the conversion.
  const onTrailingSpace = pos === wordEnd + 1 && text[wordEnd] === ' ';
  if (pos < atPos || (pos > wordEnd && !onTrailingSpace)) return false;
  const before = text.slice(0, atPos);
  const after = onTrailingSpace ? text.slice(wordEnd + 1) : text.slice(wordEnd);
  ta.value = `${before}@[${word} ]${after}`;
  ta.selectionStart = ta.selectionEnd = atPos + 2 + word.length + 1;
  _updateHighlight();
  e.preventDefault();
  return true;
}

function _composeKeydownHandler(e) {
  _mentionCtx = COMPOSE_CTX;
  if (_handleMentionSpaceKey(e)) return;
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && !_mentionState) {
    e.preventDefault();
    submitPost();
    return;
  }
  onComposeKeydown(e);
}
function _editKeydownHandler(e) {
  _mentionCtx = EDIT_CTX;
  if (_handleMentionSpaceKey(e)) return;
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && !_mentionState) {
    e.preventDefault();
    submitEdit();
    return;
  }
  onComposeKeydown(e);
}
function openCompose() {
  _mentionCtx = COMPOSE_CTX;
  pendingFiles = [];
  _uploadedAssets = [];
  const draft = (() => { try { return JSON.parse(localStorage.getItem(DRAFT_KEY) || 'null'); } catch { return null; } })();
  document.getElementById("compose-body").value = draft?.body || "";
  _updateHighlight();
  document.getElementById("compose-tags").value = draft?.tags || "";
  document.getElementById("compose-visibility").value = draft?.visibility || "contacts";
  document.getElementById("compose-progress").innerHTML = draft?.body
    ? '<div style="font-size:0.78rem;color:#888">Draft restored.</div>' : "";
  document.getElementById("compose-submit").disabled = false;
  document.getElementById("file-list").innerHTML = "";
  document.getElementById("compose-parent-id").value = "";
  document.getElementById("compose-parent-server").value = "";
  document.getElementById("compose-reply-banner").hidden = true;
  composeShowTab('write');
  document.getElementById("compose-overlay").hidden = false;
  const ta = document.getElementById("compose-body");
  ta.addEventListener('paste', _composePasteHandler);
  ta.addEventListener('keydown', _composeKeydownHandler);
  ta.focus();
}

function openComposeAsReply(postId, serverUrl, taEl) {
  openCompose();
  document.getElementById("compose-parent-id").value = postId;
  document.getElementById("compose-parent-server").value = serverUrl || '';
  const draft = taEl?.value?.trim() || '';
  if (draft) {
    document.getElementById("compose-body").value = draft;
    _updateHighlight();
  }
  const banner = document.getElementById("compose-reply-banner");
  banner.textContent = 'Replying to a post…';
  banner.hidden = false;
}
function closeCompose() {
  _activeMentionEdit = null;
  hideMentionDropdown();
  _saveDraft();
  const ta = document.getElementById("compose-body");
  ta.removeEventListener('paste', _composePasteHandler);
  ta.removeEventListener('keydown', _composeKeydownHandler);
  document.getElementById("compose-overlay").hidden = true;
  document.getElementById("compose-parent-id").value = "";
  document.getElementById("compose-parent-server").value = "";
  document.getElementById("compose-reply-banner").hidden = true;
}
function _renderFileList() {
  document.getElementById("file-list").innerHTML = _uploadedAssets.map((a, i) => {
    const statusHtml = a.uploading
      ? '<span style="color:#888;font-size:0.78rem">uploading…</span>'
      : a.error
        ? '<span style="color:#e06c6c;font-size:0.78rem">✗ failed</span>'
        : `<button onclick="_copyAssetMarkup(${i})" title="Copy markup"
             style="background:none;border:1px solid #333;border-radius:3px;color:#aaa;cursor:pointer;font-size:0.75rem;padding:0.1rem 0.4rem">copy markup</button>`;
    return `<div style="display:flex;align-items:center;gap:0.5rem;padding:0.2rem 0;font-size:0.82rem;color:#ccc">
      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.title || a.id)}</span>
      ${statusHtml}
    </div>`;
  }).join('');
}

function _copyAssetMarkup(i) {
  navigator.clipboard.writeText(_uploadedAssets[i].markup).catch(() => {});
}

function _composePasteHandler(e) {
  const items = e.clipboardData?.items;
  if (!items) return;
  for (const item of items) {
    if (item.kind === 'file' && item.type.startsWith('image/')) {
      e.preventDefault();
      const file = item.getAsFile();
      if (file) addFiles([file]);
      return;
    }
  }
}

function _insertAtCursor(ta, text) {
  const start = ta.selectionStart, end = ta.selectionEnd;
  ta.value = ta.value.substring(0, start) + text + ta.value.substring(end);
  ta.selectionStart = ta.selectionEnd = start + text.length;
  ta.dispatchEvent(new Event('input'));
}

async function addFiles(files) {
  const ta = document.getElementById("compose-body");
  for (const f of files) {
    const idx = _uploadedAssets.length;
    _uploadedAssets.push({id: null, title: f.name, media_type: f.type, markup: '', uploading: true, error: false});
    _renderFileList();
    try {
      const fd = new FormData();
      fd.append("file", f);
      const r = await apiFetch("/api/assets", {method: "POST", body: fd});
      if (r.ok) {
        const data = await r.json();
        const markup = `[asset:${data.id}]`;
        _uploadedAssets[idx] = {id: data.id, title: f.name, media_type: data.media_type, markup, uploading: false, error: false};
        _insertAtCursor(ta, (ta.value && !ta.value.endsWith('\n') ? '\n' : '') + markup + '\n');
        _saveDraft();
      } else {
        _uploadedAssets[idx].uploading = false;
        _uploadedAssets[idx].error = true;
      }
    } catch {
      _uploadedAssets[idx].uploading = false;
      _uploadedAssets[idx].error = true;
    }
    _renderFileList();
  }
}

// ── inline compose ─────────────────────────────────────────────────────────
const INLINE_CTX = { taId: 'inline-compose-body', hlId: 'inline-compose-highlight', ddId: 'inline-mention-dropdown' };

function _inlineComposeMentionInput(e) {
  const ta = e.target;
  if (!ta.id) ta.id = 'inline-compose-body';
  _mentionCtx = INLINE_CTX;
  onComposeInput();
  _repositionCommentDropdown(ta);
}

function _inlineComposeKeydown(e) {
  _mentionCtx = INLINE_CTX;
  if (_handleMentionSpaceKey(e)) return;
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && !_mentionState) {
    e.preventDefault();
    submitInlinePost();
    return;
  }
  onComposeKeydown(e);
}

async function submitInlinePost() {
  _commitActiveMentionEdit();
  const ta = document.getElementById("inline-compose-body");
  const body = _expandMentions(ta.value.trim());
  if (!body) return;
  const btn = ta.closest('div').querySelector('button.btn-primary');
  const savedText = ta.value;
  if (btn) { btn.disabled = true; btn.textContent = "Posting…"; }
  const fd = new FormData();
  fd.append("body", body);
  fd.append("tags", "[]");
  fd.append("visibility", "contacts");
  const r = await apiFetch("/api/posts", {method: "POST", body: fd});
  if (btn) { btn.disabled = false; btn.textContent = "Post"; }
  if (r.ok) {
    const post = await r.json();
    ta.value = "";
    ta.style.height = "auto";
    prependPost(post);
  } else {
    ta.value = savedText;
    const err = document.getElementById("feed-status");
    if (err) { err.textContent = "Failed to post."; setTimeout(() => { err.textContent = ""; }, 3000); }
  }
}

async function submitPost() {
  _commitActiveMentionEdit();
  const bodyText = document.getElementById("compose-body").value.trim();
  if (!bodyText && !pendingFiles.length) return;
  const tags = document.getElementById("compose-tags").value.trim().split(/\s+/).filter(Boolean);
  const prog = document.getElementById("compose-progress");
  document.getElementById("compose-submit").disabled = true;
  prog.innerHTML = '<div class="progress-item">Posting…</div>';

  const fd = new FormData();
  fd.append("body", _expandMentions(bodyText));
  fd.append("tags", JSON.stringify(tags));
  fd.append("visibility", document.getElementById("compose-visibility").value);
  const parentId = document.getElementById("compose-parent-id").value;
  const parentServer = document.getElementById("compose-parent-server").value;
  if (parentId) {
    fd.append("parent_id", parentId);
    const parentNodeId = _nodeIdForServer(parentServer);
    if (parentNodeId) fd.append("parent_node_id", parentNodeId);
    if (parentServer && parentServer !== CFG?.own_server) fd.append("parent_server_url", parentServer);
  }

  const postUrl = parentId ? "/api/posts?notify_parent=1" : "/api/posts";
  try {
    const r = await apiFetch(postUrl, {method: "POST", body: fd});
    if (r.ok) {
      const post = await r.json();
      prependPost(post);
      loadTagSidebar();
      document.getElementById("compose-body").value = "";
      document.getElementById("compose-tags").value = "";
      _clearDraft();
      prog.innerHTML = '<div class="progress-item progress-ok">&#x2713; Posted</div>';
      pendingFiles = [];
      _uploadedAssets = [];
      document.getElementById("file-list").innerHTML = "";
      setTimeout(closeCompose, 900);
    } else {
      prog.innerHTML = '<div class="progress-item progress-err">&#x2717; Error ' + r.status + '</div>';
      document.getElementById("compose-submit").disabled = false;
    }
  } catch {
    prog.innerHTML = '<div class="progress-item progress-err">&#x2717; Network error</div>';
    document.getElementById("compose-submit").disabled = false;
  }
}

function prependPost(post) {
  allPosts.unshift(post);
  document.querySelectorAll(".post-card[data-idx]").forEach(c => c.dataset.idx = parseInt(c.dataset.idx) + 1);
  const timeline = document.getElementById("timeline");
  try { timeline.insertBefore(makePostCard(post, 0), timeline.firstChild); } catch(e) { console.error('prependPost render error:', e); }
  document.getElementById("empty-msg").hidden = true;
}

// ── post context menu ──────────────────────────────────────────────────────
function closeAllPostMenus() {
  document.querySelectorAll('.post-menu-popup').forEach(m => m.remove());
}

function openPostMenu(e, idx, postId, serverUrl) {
  // data-idx is kept current by prependPost/hidePost; the baked-in idx can be stale.
  const card = e.currentTarget.closest('.post-card');
  if (card) idx = parseInt(card.dataset.idx);
  const _norm = u => (u || '').replace(/\/+$/, '');
  const isOwn = IS_OWNER && _norm(serverUrl) === _norm(CFG?.own_server);
  e.stopPropagation();
  closeAllPostMenus();
  const btn = e.currentTarget;
  const wrap = btn.parentElement;
  const popup = document.createElement('div');
  popup.className = 'post-menu-popup';
  if (isOwn) {
    popup.innerHTML =
      `<button onclick="closeAllPostMenus();openEdit(${idx})">Edit</button>`
      + `<button class="danger" onclick="closeAllPostMenus();confirmDelete(${idx})">Delete</button>`;
  } else {
    popup.innerHTML =
      `<button onclick="closeAllPostMenus();hidePost('${esc(postId)}',${idx})">Hide</button>`;
  }
  wrap.appendChild(popup);
  const dismiss = ev => { if (!popup.contains(ev.target) && ev.target !== btn) { closeAllPostMenus(); document.removeEventListener('click', dismiss, true); } };
  setTimeout(() => document.addEventListener('click', dismiss, true), 0);
}

async function hidePost(postId, idx) {
  allPosts.splice(idx, 1);
  document.querySelectorAll(".post-card[data-idx]").forEach(c => {
    const i = parseInt(c.dataset.idx);
    if (i === idx) c.remove();
    else if (i > idx) c.dataset.idx = i - 1;
  });
  _openPanels.delete(postId);
  if (_openPanels.size === 0) _stopDetailPoll();
  document.getElementById("empty-msg").hidden = allPosts.length > 0;
  loadTagSidebar();
}


// ── edit / delete ──────────────────────────────────────────────────────────
let editingIdx = -1;

function openEdit(idx) {
  _mentionCtx = EDIT_CTX;
  editingIdx = idx;
  const post = allPosts[idx];
  document.getElementById("edit-body").value = _collapseMentions(post.body || "");
  _updateHighlight();
  document.getElementById("edit-tags").value = (post.tags || []).join(" ");
  document.getElementById("edit-visibility").value = post.visibility || "contacts";
  document.getElementById("edit-status").innerHTML = "";
  document.getElementById("edit-submit").disabled = false;
  document.getElementById("edit-overlay").hidden = false;
  const ta = document.getElementById("edit-body");
  ta.addEventListener('keydown', _editKeydownHandler);
  ta.focus();
}
function closeEdit() {
  document.getElementById("edit-body").removeEventListener('keydown', _editKeydownHandler);
  document.getElementById("edit-overlay").hidden = true;
}

async function submitEdit() {
  _commitActiveMentionEdit();
  const post = allPosts[editingIdx];
  const body = _expandMentions(document.getElementById("edit-body").value);
  const tags = document.getElementById("edit-tags").value.trim().split(/\s+/).filter(Boolean);
  const visibility = document.getElementById("edit-visibility").value;
  document.getElementById("edit-submit").disabled = true;
  document.getElementById("edit-status").innerHTML = '<span style="color:#aaa">Saving…</span>';

  const r = await apiFetch("/api/posts/" + post.id, {
    method: "PATCH",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({body, tags, visibility}),
  });
  if (r.ok) {
    const updated = await r.json();
    updated._server_url = post._server_url;
    updated._server_name = post._server_name;
    allPosts[editingIdx] = updated;
    const card = document.querySelector(".post-card[data-idx='" + editingIdx + "']");
    if (card) card.replaceWith(makePostCard(updated, editingIdx));
    closeEdit();
  } else {
    document.getElementById("edit-status").innerHTML = '<span style="color:#e06c6c">Save failed.</span>';
    document.getElementById("edit-submit").disabled = false;
  }
}

async function confirmDelete(idx) {
  const post = allPosts[idx];
  if (!confirm("Delete this post? This cannot be undone.")) return;
  const r = await apiFetch("/api/posts/" + post.id, {method: "DELETE"});
  if (r.ok || r.status === 204) {
    allPosts.splice(idx, 1);
    document.querySelectorAll(".post-card[data-idx]").forEach(c => {
      const i = parseInt(c.dataset.idx);
      if (i === idx) c.remove();
      else if (i > idx) c.dataset.idx = i - 1;
    });
    _openPanels.delete(post.id);
    if (_openPanels.size === 0) _stopDetailPoll();
    document.getElementById("empty-msg").hidden = allPosts.length > 0;
    loadTagSidebar();
  }
}

// ── utilities ──────────────────────────────────────────────────────────────
function maybeClose(id, e) { if (e.target === document.getElementById(id)) document.getElementById(id).hidden = true; }
function openLightbox(src) { document.getElementById("lightbox-img").src = src; document.getElementById("lightbox").hidden = false; }
function closeLightbox() { document.getElementById("lightbox").hidden = true; document.getElementById("lightbox-img").src = ""; }
function esc(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
function mimeIcon(mt) {
  if (!mt) return "📄";
  if (mt.startsWith("video/")) return "🎬";
  if (mt.startsWith("audio/")) return "🎵";
  if (mt === "application/pdf") return "📋";
  return "📄";
}
function fmtDate(ts) {
  if (!ts) return "";
  const d = new Date(ts / 1_000_000);
  const age = Date.now() - d.getTime();
  const mins  = Math.floor(age / 60_000);
  const hours = Math.floor(age / 3_600_000);
  const days  = Math.floor(age / 86_400_000);
  if (age < 60_000)  return "now";
  if (mins  < 60)    return mins  === 1 ? "1 min ago"  : `${mins} mins ago`;
  if (hours < 24)    return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
  if (days  < 7) {
    const hhmm = d.toLocaleTimeString(undefined, {hour:"2-digit", minute:"2-digit"});
    const day  = d.toLocaleDateString(undefined, {weekday:"short"});
    return `${hhmm} ${day}`;
  }
  return d.toLocaleDateString(undefined, {month:"short", day:"numeric"});
}

function fmtDateFull(ts) {
  if (!ts) return "";
  return new Date(ts / 1_000_000).toLocaleString(undefined, {dateStyle:"full", timeStyle:"medium"});
}
function fmtSize(b) { if (b < 1024) return b + " B"; if (b < 1048576) return (b/1024).toFixed(1) + " KB"; return (b/1048576).toFixed(1) + " MB"; }

// ── profile ────────────────────────────────────────────────────────────────
function openProfile() { loadProfileAvatar(); _updateThemeButtons(); document.getElementById("profile-overlay").hidden = false; }
function closeProfile() { document.getElementById("profile-overlay").hidden = true; }

function downloadBackup() {
  window.location.href = "/api/backup" + clientTokenParam(false);
}

function _onReleaseCheckbox(cb) {
  const passEl = document.getElementById('release-passphrase');
  const btnEl = document.getElementById('release-btn');
  const enabled = cb.checked;
  passEl.disabled = !enabled;
  passEl.style.opacity = enabled ? '1' : '0.5';
  btnEl.disabled = !enabled;
  btnEl.style.opacity = enabled ? '1' : '0.4';
  if (!enabled) { passEl.value = ''; document.getElementById('release-delete-registry').checked = false; document.getElementById('release-delete-warning').hidden = true; }
}

function _onReleaseDeleteRegistry(cb) {
  document.getElementById('release-delete-warning').hidden = !cb.checked;
}

async function releaseNode() {
  const passphrase = (document.getElementById('release-passphrase')?.value || '').trim();
  const statusEl = document.getElementById('release-status');
  if (!passphrase) { statusEl.style.color = 'var(--error)'; statusEl.textContent = 'Enter your passphrase to confirm.'; return; }
  if (!confirm('This will permanently erase ALL node data — posts, contacts, settings, and files. This cannot be undone.\n\nContinue?')) return;
  statusEl.style.color = 'var(--text-4)'; statusEl.textContent = 'Releasing…';
  try {
    const deleteFromRegistry = document.getElementById('release-delete-registry')?.checked || false;
    const r = await apiFetch('/api/setup/release', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({passphrase, delete_from_registry: deleteFromRegistry}),
    });
    if (r.ok || r.status === 204) {
      statusEl.style.color = 'var(--ok)'; statusEl.textContent = 'Node released. Reloading…';
      setTimeout(() => window.location.reload(), 1200);
    } else {
      const err = await r.json().catch(() => ({}));
      statusEl.style.color = 'var(--error)'; statusEl.textContent = err.detail || 'Release failed.';
    }
  } catch (e) {
    statusEl.style.color = 'var(--error)'; statusEl.textContent = 'Error: ' + e.message;
  }
}

async function downloadPrivateKey() {
  const passphrase = document.getElementById("privkey-passphrase").value;
  const status = document.getElementById("privkey-status");
  if (!passphrase) { status.style.color = "var(--error)"; status.textContent = "Enter your passphrase."; return; }
  status.style.color = "var(--text-4)"; status.textContent = "Verifying…";
  const r = await apiFetch("/api/profile/private-key", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({passphrase}),
  });
  if (r.status === 401) { status.style.color = "#e06c6c"; status.textContent = "Wrong passphrase."; return; }
  if (!r.ok) { status.style.color = "#e06c6c"; status.textContent = "Download failed."; return; }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "contacc-private-key.pem"; a.click();
  URL.revokeObjectURL(url);
  document.getElementById("privkey-passphrase").value = "";
  status.style.color = "#4caf50"; status.textContent = "Downloaded.";
  setTimeout(() => { status.textContent = ""; }, 3000);
}

// ── mention notifications ──────────────────────────────────────────────────
let _mentionsData = [];

async function loadMentions() {
  const r = await apiFetch("/api/notifications/mentions");
  if (!r.ok) return;
  _mentionsData = (await r.json()).notifications || [];
  const unread = _mentionsData.filter(m => !m.seen).length;
  const badge = document.getElementById("mentions-badge");
  const wrap = document.getElementById("mentions-wrap");
  if (wrap) wrap.style.display = "";
  if (badge) {
    badge.hidden = unread === 0;
    badge.textContent = unread > 9 ? "9+" : String(unread);
  }
  // Show DM button alongside mentions; start background DM badge refresh
  const dmWrap = document.getElementById("dm-wrap");
  if (dmWrap) dmWrap.style.display = "";
  if (!_dmPollTimer) { _dmPollTimer = setInterval(_loadDmThreads, 30_000); _loadDmThreads(); }
}

function _panelTop(btnId) {
  const btn = document.getElementById(btnId);
  if (!btn) return '60px';
  return (btn.getBoundingClientRect().bottom + 6) + 'px';
}

function _toggleMentionsPanel() {
  const panel = document.getElementById("mentions-panel");
  if (panel.hidden) {
    panel.style.top = _panelTop("mentions-btn");
    _renderMentionsList();
    panel.hidden = false;
    setTimeout(() => document.addEventListener("click", _closeMentionsPanelOutside, {once: true}), 0);
  } else {
    panel.hidden = true;
  }
}

function _closeMentionsPanelOutside(e) {
  const wrap = document.getElementById("mentions-wrap");
  if (wrap && !wrap.contains(e.target)) {
    document.getElementById("mentions-panel").hidden = true;
  } else {
    setTimeout(() => document.addEventListener("click", _closeMentionsPanelOutside, {once: true}), 0);
  }
}

function _renderMentionsList() {
  const list = document.getElementById("mentions-list");
  if (!_mentionsData.length) {
    list.innerHTML = '<div style="padding:0.75rem;font-size:0.85rem;color:#555;text-align:center">Nothing yet</div>';
    return;
  }
  const unread = _mentionsData.filter(m => !m.seen).length;
  const header = `<div style="display:flex;justify-content:space-between;align-items:center;padding:0.4rem 0.75rem;border-bottom:1px solid #252525;font-size:0.75rem;color:#555">
    <span>${unread > 0 ? unread + ' unread' : 'All caught up'}</span>
    ${unread > 0 ? `<button onclick="_markMentionsSeen()" style="background:none;border:none;color:#555;cursor:pointer;font-size:0.75rem;padding:0" onmouseover="this.style.color='#aaa'" onmouseout="this.style.color='#555'">Clear all</button>` : ''}
  </div>`;
  list.innerHTML = header + _mentionsData.map(m => {
    const _actorId = m.author_node_id || m.author_server || '';
    const contact = (CFG?.contacts || []).find(c => c.node_id === _actorId || c.url === _actorId);
    const _resolved = _actorId ? _resolveIdentity(_actorId, '') : null;
    const _actorName = m.actor_name && !m.actor_name.startsWith('http') ? m.actor_name : null;
    const name = _actorName || (contact ? (contact.name || m.author_handle) : (_resolved?.name || m.author_handle || 'Satan'));
    const time = fmtDate(m.received_at);
    const dot = m.seen ? '' : '<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:#4285f4;flex-shrink:0;margin-top:3px"></span>';
    let text;
    if (m.notif_type === 'reaction') text = `${name} reacted ${m.emoji || ''} to your post`;
    else if (m.notif_type === 'reply') text = `${name} replied to your post`;
    else text = `${name} mentioned you`;
    return `<div onclick="_jumpToMention('${esc(m.post_id)}','${esc(m.post_node_id||'')}','${esc(m.id)}')" style="display:flex;gap:0.5rem;align-items:flex-start;padding:0.55rem 0.75rem;cursor:pointer;border-bottom:1px solid #1e1e1e" onmouseover="this.style.background='#252525'" onmouseout="this.style.background=''">
      ${dot || '<span style="display:inline-block;width:7px;flex-shrink:0"></span>'}
      <div style="flex:1;min-width:0">
        <div style="font-size:0.85rem;color:#ccc;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(text)}</div>
        <div style="font-size:0.75rem;color:#555">${esc(time)}</div>
      </div>
    </div>`;
  }).join('');
}

async function _markMentionsSeen() {
  await apiFetch("/api/notifications/mentions/mark-seen", {method: "POST"});
  _mentionsData.forEach(m => m.seen = true);
  const badge = document.getElementById("mentions-badge");
  if (badge) badge.hidden = true;
  _renderMentionsList();
}

async function _jumpToMention(postId, postNodeId, notifId) {
  document.getElementById("mentions-panel").hidden = true;
  if (notifId) {
    apiFetch("/api/notifications/mentions/" + encodeURIComponent(notifId) + "/seen", {method: "POST"}).catch(() => {});
    const notif = _mentionsData.find(m => m.id === notifId);
    if (notif && !notif.seen) {
      notif.seen = true;
      const unread = _mentionsData.filter(m => !m.seen).length;
      const badge = document.getElementById("mentions-badge");
      if (badge) { badge.hidden = unread === 0; badge.textContent = unread > 9 ? "9+" : String(unread || ''); }
    }
  }
  const serverUrl = postNodeId ? await _fetchServerForNodeId(postNodeId) : '';
  openPostOverlay(postId, serverUrl);
}

// ── DMs ───────────────────────────────────────────────────────────────────────
let _dmThreads = [];
let _dmActiveThread = null;
let _dmMessages = [];
let _dmPollTimer = null;
let _dmHighlightIdx = -1;

function _dmHighlightUpdate(idx) {
  const items = document.querySelectorAll('#dm-threads-list [data-tid]');
  _dmHighlightIdx = Math.max(-1, Math.min(idx, items.length - 1));
  items.forEach((el, i) => {
    el.style.background = i === _dmHighlightIdx ? '#2a2a2a' : '';
  });
  if (_dmHighlightIdx >= 0) items[_dmHighlightIdx].scrollIntoView({block: 'nearest'});
}

function _dmKeyNav(e) {
  const listView = document.getElementById('dm-thread-list-view');
  if (!listView || listView.hidden) return;
  if (e.key === 'ArrowDown') { e.preventDefault(); _dmHighlightUpdate(_dmHighlightIdx + 1); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); _dmHighlightUpdate(_dmHighlightIdx - 1); }
  else if (e.key === 'Enter' && _dmHighlightIdx >= 0) {
    e.preventDefault();
    const items = document.querySelectorAll('#dm-threads-list [data-tid]');
    const el = items[_dmHighlightIdx];
    if (el) _dmOpenThread(el.dataset.tid, el.dataset.pname);
  }
}

function _dmToggleExpand() {
  const panel = document.getElementById("dm-panel");
  const expanded = panel.classList.toggle("dm-expanded");
  document.querySelectorAll(".dm-expand-btn").forEach(b => {
    b.textContent = expanded ? "⤡" : "⤢";
    b.title = expanded ? "Collapse" : "Expand";
  });
  if (expanded) {
    const hdr = document.querySelector("header");
    const top = hdr ? Math.round(hdr.getBoundingClientRect().bottom) + 6 : 70;
    panel.style.top = top + "px";
  } else {
    panel.style.top = _panelTop("dm-btn");
  }
}

function _dmResetExpand() {
  const panel = document.getElementById("dm-panel");
  panel.classList.remove("dm-expanded");
  document.querySelectorAll(".dm-expand-btn").forEach(b => {
    b.textContent = "⤢";
    b.title = "Expand";
  });
}

function _toggleDmPanel() {
  const panel = document.getElementById("dm-panel");
  const wasHidden = panel.hidden;
  document.getElementById("mentions-panel").hidden = true;
  panel.hidden = !wasHidden;
  if (!wasHidden) {
    _dmActiveThread = null;
    _dmHighlightIdx = -1;
    document.removeEventListener('keydown', _dmKeyNav);
    _dmResetExpand();
    if (_openPanels.size === 0) _stopDetailPoll();
    return;
  }
  panel.style.top = _panelTop("dm-btn");
  _openSSE();  // ensure SSE is active while DM panel is open
  _dmHighlightIdx = -1;
  document.addEventListener('keydown', _dmKeyNav);
  _dmBackToThreads();
  _loadDmThreads();  // fresh fetch when panel opens
  setTimeout(() => document.addEventListener('click', _closeDmPanelOutside, {once: true}), 0);
}

function _closeDmPanelOutside(e) {
  const panel = document.getElementById("dm-panel");
  const btn = document.getElementById("dm-btn");
  if (!panel || panel.hidden) return;
  if (panel.contains(e.target) || e.target === btn) {
    setTimeout(() => document.addEventListener('click', _closeDmPanelOutside, {once: true}), 0);
    return;
  }
  panel.hidden = true;
  _dmActiveThread = null;
  _dmHighlightIdx = -1;
  document.removeEventListener('keydown', _dmKeyNav);
  _dmResetExpand();
  if (_openPanels.size === 0) _stopDetailPoll();
}

async function _loadDmThreads() {
  const r = await apiFetch("/api/dm/threads");
  if (!r.ok) return;
  const d = await r.json();
  _dmThreads = d.threads || [];
  _renderDmThreads();
  // Update badge
  const unread = _dmThreads.reduce((s, t) => s + (t.unread_count || 0), 0);
  const badge = document.getElementById("dm-badge");
  if (badge) { badge.hidden = unread === 0; badge.textContent = unread > 9 ? "9+" : unread; }
}

// Resolve a group member's display name the same lazy, best-effort way the
// rest of the UI resolves identities — from server-supplied member_names
// (itself just a contact-list lookup, see api_dm_threads), falling back to a
// truncated node_id. No separate name-caching machinery for groups.
function _dmMemberName(thread, nodeId) {
  if (nodeId === CFG?.own_node_id) return 'you';
  const known = thread?.member_names?.[nodeId];
  return known || (nodeId ? nodeId.slice(0, 8) : '?');
}

function _renderDmThreads() {
  const list = document.getElementById("dm-threads-list");
  if (!list) return;
  if (!_dmThreads.length) {
    list.innerHTML = '<div style="padding:0.75rem;font-size:0.82rem;color:var(--text-4)">No messages yet.</div>';
    return;
  }
  list.innerHTML = _dmThreads.map(t => {
    const isGroup = !!t.group_id;
    const displayName = isGroup ? (t.group_name || 'Group') : (t.peer_name || t.peer_node_id || '');
    const name = esc(displayName);
    const initial = esc((displayName || '?')[0].toUpperCase());
    const unread = t.unread_count || 0;
    const photoUrl = (!isGroup && t.peer_node_id) ? '/api/contacts/photo?node_id=' + encodeURIComponent(t.peer_node_id) : '';
    const avatarHtml = isGroup
      ? `<span class="post-author-initials" style="width:28px;height:28px;font-size:0.85rem">👥</span>`
      : (photoUrl
        ? `<img src="${photoUrl}" class="post-author-avatar" style="width:28px;height:28px" alt=""
             onerror="this.hidden=true;this.nextElementSibling.hidden=false">
           <span class="post-author-initials" style="width:28px;height:28px;font-size:0.7rem" hidden>${initial}</span>`
        : `<span class="post-author-initials" style="width:28px;height:28px;font-size:0.7rem">${initial}</span>`);
    const contactBadge = (!isGroup && t.is_contact)
      ? `<span style="font-size:0.65rem;color:var(--text-4);border:1px solid var(--border);border-radius:3px;padding:0.05rem 0.3rem;white-space:nowrap">contact</span>`
      : (isGroup
        ? `<span style="font-size:0.65rem;color:var(--text-4);border:1px solid var(--border);border-radius:3px;padding:0.05rem 0.3rem;white-space:nowrap">${(t.members||[]).length} members</span>`
        : '');
    const unreadBadge = unread
      ? `<span style="background:#4285f4;color:#fff;border-radius:10px;padding:0.1rem 0.4rem;font-size:0.7rem;font-weight:600">${unread}</span>`
      : '';
    return `<div data-tid="${esc(t.thread_id)}" data-pname="${esc(displayName)}"
      onclick="_dmOpenThread(this.dataset.tid,this.dataset.pname)"
      style="padding:0.4rem 0.75rem;cursor:pointer;display:flex;align-items:center;gap:0.5rem;border-bottom:1px solid var(--border)"
      onmouseover="this.style.background='var(--surface-3)'" onmouseout="this.style.background=''">
      ${avatarHtml}
      <span style="flex:1;font-size:0.88rem;color:var(--text-1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${name}</span>
      ${contactBadge}${unreadBadge}
    </div>`;
  }).join('');
}

async function _dmOpenThread(threadId, peerName) {
  _dmActiveThread = threadId;
  _dmHighlightIdx = -1;
  document.getElementById("dm-conv-name").textContent = peerName;
  document.getElementById("dm-thread-list-view").hidden = true;
  document.getElementById("dm-conversation-view").hidden = false;
  await _loadDmThreads();
  document.getElementById("dm-conv-members-btn").hidden = !_dmThreads.find(t => t.thread_id === threadId)?.group_id;
  await _loadDmMessages(threadId);
  document.getElementById("dm-compose").focus();
  await apiFetch("/api/dm/threads/" + threadId + "/seen", {method: "POST"});
}

async function _loadDmMessages(threadId) {
  const r = await apiFetch("/api/dm/messages/" + threadId + "?limit=100");
  if (!r.ok) {
    document.getElementById("dm-messages-list").innerHTML =
      '<div style="text-align:center;color:#666;font-size:0.82rem;padding:1rem">Could not load messages.</div>';
    return;
  }
  const d = await r.json();
  _dmMessages = d.messages || [];
  _renderDmMessages();
}

function _renderDmMessages() {
  const list = document.getElementById("dm-messages-list");
  if (!list) return;
  const thread = _dmThreads.find(t => t.thread_id === _dmActiveThread);
  const isGroup = !!thread?.group_id;
  list.innerHTML = _dmMessages.map(m => {
    const out = m.direction === 'out';
    const time = m.created_at ? fmtDate(m.created_at) : '';
    const delivered = out ? (m.delivered_at ? '' : ' style="opacity:0.5"') : '';
    // Attribution: in a group thread, every inbound bubble names its original
    // author (the relay only ever exposes their identity via sender_node_id —
    // see the wire-format note's chat_message section); 1:1 threads need none,
    // direction alone disambiguates there.
    const attribution = (isGroup && !out)
      ? `<span style="font-size:0.7rem;color:var(--text-4);margin-bottom:0.1rem">${esc(_dmMemberName(thread, m.sender_node_id))}</span>`
      : '';
    return `<div style="display:flex;flex-direction:column;align-items:${out?'flex-end':'flex-start'}"${delivered}>
      ${attribution}
      <div class="dm-bubble" style="max-width:80%;background:${out?'#1a3360':'#252525'};border-radius:8px;padding:0.4rem 0.65rem;font-size:0.88rem;color:#e0e0e0;word-break:break-word">${renderBodyText(m.body)}</div>
      <span style="font-size:0.65rem;color:var(--text-4);margin-top:0.15rem">${esc(time)}${out&&!m.delivered_at?' ·':''}</span>
    </div>`;
  }).join('');
  list.scrollTop = list.scrollHeight;
}

async function _dmSend() {
  if (!_dmActiveThread) return;
  const ta = document.getElementById("dm-compose");
  const body = ta.value.trim();
  if (!body) return;

  let payload;
  if (_dmActiveThread.startsWith("__new__:")) {
    const peer_url = _dmActiveThread.slice("__new__:".length);
    // Use node_id from contact list if available; otherwise fetch /node
    const contact = (CFG.contacts || []).find(c => c.url === peer_url);
    const peer_node_id = contact?.node_id;
    if (!peer_node_id) { alert("Contact's node ID is not known — cannot send message."); return; }
    payload = {peer_node_id, peer_url, body};
  } else {
    const thread = _dmThreads.find(t => t.thread_id === _dmActiveThread);
    if (!thread) return;
    payload = thread.group_id
      ? {group_id: thread.group_id, body}
      : {peer_node_id: thread.peer_node_id, peer_url: thread.peer_url, body};
  }

  ta.value = ""; ta.style.height = "";
  const r = await apiFetch("/api/dm/send", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    ta.value = body;
    const err = document.getElementById("dm-send-error");
    if (err) { err.textContent = "Send failed — try again."; setTimeout(() => err.textContent = "", 4000); }
    return;
  }
  // After first message, update active thread to real thread_id
  const d = await r.json();
  if (_dmActiveThread.startsWith("__new__:")) {
    _dmActiveThread = d.thread_id;
  }
  await _loadDmThreads();
  await _loadDmMessages(_dmActiveThread);
}

async function _dmStartNew(peerUrl) {
  const contact = (CFG.contacts || []).find(c => c.url === peerUrl);

  // Resolve node_id before opening the panel — no thread without a known peer identity
  if (!contact?.node_id) {
    try {
      const nr = await fetch(peerUrl.replace(/\/$/, '') + "/node");
      if (!nr.ok) { alert("Could not reach contact's node."); return; }
      const nd = await nr.json();
      const nodeId = nd.node_id || nd.user_id;
      if (!nodeId) { alert("Contact's node doesn't report a node ID."); return; }
      if (contact) {
        contact.node_id = nodeId;
        apiFetch("/api/contacts", {method:"PATCH",
          headers:{"Content-Type":"application/json"},
          body: JSON.stringify({url: peerUrl, node_id: nodeId})});
      }
    } catch { alert("Could not reach contact's node."); return; }
  }

  const panel = document.getElementById("dm-panel");
  document.getElementById("mentions-panel").hidden = true;
  panel.style.top = _panelTop("dm-btn");
  panel.hidden = false;
  setTimeout(() => document.addEventListener('click', _closeDmPanelOutside, {once: true}), 0);
  if (!_dmPollTimer) _dmPollTimer = setInterval(_loadDmThreads, 30_000);
  await _loadDmThreads();

  const thread = _dmThreads.find(t => t.peer_node_id === contact?.node_id || t.peer_url === peerUrl);
  if (thread) {
    await _dmOpenThread(thread.thread_id, thread.peer_name || (contact && contact.name) || peerUrl);
  } else {
    _dmActiveThread = "__new__:" + peerUrl;
    const name = (contact && contact.name) || peerUrl;
    document.getElementById("dm-conv-name").textContent = name;
    document.getElementById("dm-conv-members-btn").hidden = true;
    document.getElementById("dm-thread-list-view").hidden = true;
    document.getElementById("dm-conversation-view").hidden = false;
    document.getElementById("dm-messages-list").innerHTML =
      '<div style="text-align:center;color:#555;font-size:0.82rem;padding:1rem">Start of your conversation</div>';
    document.getElementById("dm-compose").focus();
  }
}

function _dmBackToThreads() {
  _dmActiveThread = null;
  document.getElementById("dm-thread-list-view").hidden = false;
  document.getElementById("dm-conversation-view").hidden = true;
  _renderDmThreads();
}

// ── group creation ────────────────────────────────────────────────────────────

function _dmShowNewGroup() {
  const list = document.getElementById("new-group-contacts");
  const eligible = (CFG.contacts || []).filter(c => c.node_id);
  if (!eligible.length) {
    list.innerHTML = '<div style="font-size:0.82rem;color:#555">Add a contact with a known node ID first.</div>';
  } else {
    list.innerHTML = eligible.map(c => `
      <label style="display:flex;align-items:center;gap:0.5rem;font-size:0.85rem;color:#ddd;cursor:pointer">
        <input type="checkbox" value="${esc(c.node_id)}"> ${esc(c.name || c.node_id)}
      </label>`).join('');
  }
  document.getElementById("new-group-name").value = "";
  document.getElementById("new-group-error").textContent = "";
  document.getElementById("new-group-overlay").hidden = false;
}

async function _dmCreateGroup() {
  const name = document.getElementById("new-group-name").value.trim();
  const member_node_ids = [...document.querySelectorAll("#new-group-contacts input:checked")].map(el => el.value);
  const err = document.getElementById("new-group-error");
  if (!name) { err.textContent = "Enter a group name."; return; }
  if (!member_node_ids.length) { err.textContent = "Pick at least one member."; return; }

  err.textContent = "";
  const r = await apiFetch("/api/dm/groups", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({name, member_node_ids}),
  });
  if (!r.ok) { err.textContent = "Could not create group — try again."; return; }
  const d = await r.json();
  document.getElementById("new-group-overlay").hidden = true;
  await _loadDmThreads();
  await _dmOpenThread(d.thread_id, d.group_name);
}

// ── group membership / management ─────────────────────────────────────────────

function _dmShowGroupMembers() {
  const thread = _dmThreads.find(t => t.thread_id === _dmActiveThread);
  if (!thread || !thread.group_id) return;
  const amCreator = thread.group_creator_id === CFG?.own_node_id;

  document.getElementById("group-members-title").textContent = thread.group_name || "Group members";
  document.getElementById("group-members-error").textContent = "";

  const renameRow = document.getElementById("group-rename-row");
  renameRow.hidden = !amCreator;
  document.getElementById("group-rename-name").value = thread.group_name || "";

  const members = thread.members || [];
  document.getElementById("group-members-list").innerHTML = members.map(nid => {
    const label = nid === thread.group_creator_id
      ? `${esc(_dmMemberName(thread, nid))} <span style="color:#555">(creator)</span>`
      : esc(_dmMemberName(thread, nid));
    return `<div style="font-size:0.85rem;color:#ddd;padding:0.2rem 0">${label}</div>`;
  }).join('');

  // Anyone may ask to add a contact who isn't already a member (v1 add policy:
  // any current member's request is granted — see request_add_group_member).
  const addSelect = document.getElementById("group-add-member-select");
  const candidates = (CFG.contacts || []).filter(c => c.node_id && !members.includes(c.node_id));
  const addRow = document.getElementById("group-add-member-row");
  if (candidates.length) {
    addRow.hidden = false;
    addSelect.innerHTML = candidates.map(c => `<option value="${esc(c.node_id)}">${esc(c.name || c.node_id)}</option>`).join('');
  } else {
    addRow.hidden = true;
  }

  // The creator can't leave their own group yet (no surrogate-creator failover) —
  // surfacing that as a disabled control beats letting the request fail silently.
  const leaveBtn = document.getElementById("group-leave-btn");
  leaveBtn.disabled = amCreator;
  leaveBtn.title = amCreator ? "The group's creator can't leave it yet" : "";
  leaveBtn.style.opacity = amCreator ? "0.5" : "";

  document.getElementById("group-members-overlay").hidden = false;
}

async function _dmAddGroupMember() {
  const thread = _dmThreads.find(t => t.thread_id === _dmActiveThread);
  const node_id = document.getElementById("group-add-member-select").value;
  const err = document.getElementById("group-members-error");
  if (!thread || !node_id) return;
  err.textContent = "";
  const r = await apiFetch(`/api/dm/groups/${thread.group_id}/members`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({node_id}),
  });
  if (!r.ok) { err.textContent = "Could not add member — try again."; return; }
  await _loadDmThreads();
  _dmShowGroupMembers();
}

async function _dmRenameGroup() {
  const thread = _dmThreads.find(t => t.thread_id === _dmActiveThread);
  const name = document.getElementById("group-rename-name").value.trim();
  const err = document.getElementById("group-members-error");
  if (!thread || !name) return;
  err.textContent = "";
  const r = await apiFetch(`/api/dm/groups/${thread.group_id}/rename`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({name}),
  });
  if (!r.ok) { err.textContent = "Could not rename group — try again."; return; }
  await _loadDmThreads();
  document.getElementById("dm-conv-name").textContent = name;
  _dmShowGroupMembers();
}

async function _dmLeaveGroup() {
  const thread = _dmThreads.find(t => t.thread_id === _dmActiveThread);
  if (!thread || thread.group_creator_id === CFG?.own_node_id) return;
  if (!confirm(`Leave "${thread.group_name || 'this group'}"?`)) return;
  const err = document.getElementById("group-members-error");
  err.textContent = "";
  const r = await apiFetch(`/api/dm/groups/${thread.group_id}/leave`, {method: "POST"});
  if (!r.ok) { err.textContent = "Could not leave group — try again."; return; }
  document.getElementById("group-members-overlay").hidden = true;
  _dmBackToThreads();
  await _loadDmThreads();
}

// ── contact edit modal ────────────────────────────────────────────────────────
let _ceUrl = null;
const _CE_CATS = [
  {key:'family',        label:'Family'},
  {key:'close_friends', label:'Close Friends'},
  {key:'friends',       label:'Friends'},
  {key:'colleagues',    label:'Colleagues'},
  {key:'acquaintances', label:'Acquaintances'},
];

function openContactEdit(url) {
  const contact = (CFG.servers || []).find(s => s.url === url);
  if (!contact) return;
  _ceUrl = url;

  const prof = serverProfiles[url];
  const initial = (contact.name || '?')[0].toUpperCase();
  const avatarEl = document.getElementById('ce-avatar');
  if (prof?.photo_url) {
    avatarEl.innerHTML = `<img src="${esc(prof.photo_url)}" style="width:40px;height:40px;border-radius:50%;object-fit:cover">`;
  } else {
    avatarEl.textContent = initial;
  }
  document.getElementById('ce-name').textContent = contact.name || url;
  document.getElementById('ce-url').textContent = url;
  document.getElementById('ce-description').value = contact.description || '';
  document.getElementById('ce-tag').value = contact.tag || '';

  // Build category sliders
  const container = document.getElementById('ce-cats');
  container.innerHTML = '';
  _CE_CATS.forEach(({key, label}) => {
    const val = contact[key] ?? 0;
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;gap:0.6rem';
    row.innerHTML = `
      <span style="width:110px;font-size:0.82rem;color:#aaa;flex-shrink:0">${label}</span>
      <input type="range" min="0" max="1" step="0.05" value="${val}"
        style="flex:1;accent-color:#4285f4"
        oninput="this.nextElementSibling.textContent=parseFloat(this.value).toFixed(2)"
        data-cat="${key}">
      <span style="width:2.5rem;text-align:right;font-size:0.82rem;color:#90c0ff;font-variant-numeric:tabular-nums">${val.toFixed(2)}</span>`;
    container.appendChild(row);
  });

  document.getElementById('ce-status').textContent = '';
  document.getElementById('contact-edit-overlay').hidden = false;
  document.getElementById('ce-description').focus();
}

function closeContactEdit() {
  document.getElementById('contact-edit-overlay').hidden = true;
  _ceUrl = null;
}

async function saveContactEdit() {
  if (!_ceUrl) return;
  const status = document.getElementById('ce-status');
  status.textContent = 'Saving…'; status.style.color = '#888';

  const patchBody = {
    url: _ceUrl,
    description: document.getElementById('ce-description').value.trim() || '',
    tag: document.getElementById('ce-tag').value.trim(),
  };
  document.getElementById('ce-cats').querySelectorAll('input[data-cat]').forEach(el => {
    patchBody[el.dataset.cat] = parseFloat(el.value);
  });

  const r = await apiFetch('/api/contacts', {
    method: 'PATCH',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(patchBody),
  });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    status.style.color = '#e06c6c'; status.textContent = d.detail || 'Save failed.';
    return;
  }
  const cfg = await (await apiFetch('/api/config')).json();
  _setCFG(cfg);
  renderServerList();
  const updated = (cfg.servers || []).find(s => s.url === _ceUrl);
  if (updated) _serverPollIntervals[_ceUrl] = _computePollInterval(_serverActivity7d[_ceUrl] || 0, updated.poll_weight);
  closeContactEdit();
}

async function checkDefaultPassphrase() {
  try {
    const r = await apiFetch("/api/setup/passphrase-is-default");
    if (r.ok) {
      const data = await r.json();
      document.getElementById("default-passphrase-banner").hidden = !data.is_default;
    }
  } catch (_) {}
}

async function checkEscrow() {
  try {
    const r = await apiFetch("/api/setup/has-escrow");
    if (r.ok) {
      const data = await r.json();
      document.getElementById("no-escrow-banner").hidden = data.has_escrow;
    }
  } catch (_) {}
}

function openEscrowPanel() {
  document.getElementById("ce-pass").value = "";
  document.getElementById("ce-confirm").value = "";
  document.getElementById("ce-error").textContent = "";
  document.getElementById("create-escrow-overlay").hidden = false;
}

async function doCreateEscrow() {
  const pass = document.getElementById("ce-pass").value;
  const confirm = document.getElementById("ce-confirm").value;
  const err = document.getElementById("ce-error");
  if (!pass) { err.textContent = "Please enter a recovery passphrase."; return; }
  if (pass !== confirm) { err.style.color = "#e06c6c"; err.textContent = "Passphrases don't match."; return; }
  err.style.color = "#888"; err.textContent = "Setting up…";
  const r = await apiFetch("/api/setup/create-identity-escrow", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({owner_passphrase: pass}),
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    err.style.color = "#e06c6c"; err.textContent = e.detail || "Failed."; return;
  }
  document.getElementById("create-escrow-overlay").hidden = true;
  document.getElementById("no-escrow-banner").hidden = true;
}

function openDefaultPassphrasePanel() {
  document.getElementById("dp-new").value = "";
  document.getElementById("dp-confirm").value = "";
  document.getElementById("dp-error").textContent = "";
  document.getElementById("default-passphrase-overlay").hidden = false;
}

async function doSetDefaultPassphrase() {
  const newPass = document.getElementById("dp-new").value;
  const confirm = document.getElementById("dp-confirm").value;
  const err = document.getElementById("dp-error");
  if (!newPass) { err.textContent = "Please enter a new passphrase."; return; }
  if (newPass !== confirm) { err.textContent = "Passphrases don't match."; return; }
  err.style.color = "#888"; err.textContent = "Setting passphrase…";
  const r = await apiFetch("/api/settings/change-passphrase", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({current_passphrase: "foobar", new_passphrase: newPass, confirm_new_passphrase: confirm, tang_enabled: document.getElementById("dp-tang").checked}),
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    err.style.color = "#e06c6c"; err.textContent = e.detail || "Failed."; return;
  }
  // Also update the owner passphrase if an escrow exists
  await apiFetch("/api/setup/change-owner-passphrase", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({old_owner_passphrase: "foobar", new_owner_passphrase: newPass}),
  }).catch(() => {});
  document.getElementById("default-passphrase-overlay").hidden = true;
  document.getElementById("default-passphrase-banner").hidden = true;
}

async function changePassphrase() {
  const current = document.getElementById("cp-current").value;
  const newPass = document.getElementById("cp-new").value;
  const confirm = document.getElementById("cp-confirm").value;
  const status = document.getElementById("cp-status");
  if (!current || !newPass) { status.style.color = "#e06c6c"; status.textContent = "All fields required."; return; }
  if (newPass !== confirm) { status.style.color = "#e06c6c"; status.textContent = "New passphrases don't match."; return; }
  status.style.color = "#888"; status.textContent = "Changing passphrase (re-encrypting files)…";
  const r = await apiFetch("/api/settings/change-passphrase", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({current_passphrase: current, new_passphrase: newPass, confirm_new_passphrase: confirm, tang_enabled: document.getElementById("cp-tang")?.checked ?? true}),
  });
  if (r.status === 403) { status.style.color = "#e06c6c"; status.textContent = "Wrong current passphrase."; return; }
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    status.style.color = "#e06c6c"; status.textContent = err.detail || "Failed to change passphrase."; return;
  }
  document.getElementById("cp-current").value = "";
  document.getElementById("cp-new").value = "";
  document.getElementById("cp-confirm").value = "";
  status.style.color = "#4caf50"; status.textContent = "Passphrase changed.";
  setTimeout(() => { status.textContent = ""; }, 4000);
}

async function refreshDelegation() {
  const pass = document.getElementById("rd-pass").value;
  const status = document.getElementById("rd-status");
  if (!pass) { status.style.color = "#e06c6c"; status.textContent = "Owner passphrase required."; return; }
  status.style.color = "#888"; status.textContent = "Refreshing…";
  const r = await apiFetch("/api/setup/refresh-delegation", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({owner_passphrase: pass}),
  });
  if (r.ok) {
    document.getElementById("rd-pass").value = "";
    status.style.color = "#4caf50"; status.textContent = "Delegation cert refreshed. Heartbeat sent.";
    setTimeout(() => { status.textContent = ""; }, 6000);
  } else {
    const e = await r.json().catch(() => ({}));
    status.style.color = "#e06c6c"; status.textContent = e.detail || "Failed.";
  }
}

async function uploadEscrowFromSettings() {
  const key = document.getElementById("eu-key").value.trim();
  const pass = document.getElementById("eu-pass").value;
  const status = document.getElementById("eu-status");
  if (!key) { status.style.color = "#e06c6c"; status.textContent = "Identity private key required."; return; }
  if (!pass) { status.style.color = "#e06c6c"; status.textContent = "Owner passphrase required."; return; }
  status.style.color = "#888"; status.textContent = "Uploading…";
  const r = await fetch("/setup/escrow-identity-key", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({identity_private_key: key, owner_passphrase: pass}),
  });
  if (r.ok) {
    document.getElementById("eu-key").value = "";
    document.getElementById("eu-pass").value = "";
    status.style.color = "#4caf50"; status.textContent = "Identity key escrowed in registry.";
    setTimeout(() => { status.textContent = ""; }, 5000);
  } else {
    const d = await r.json().catch(() => ({}));
    status.style.color = "#e06c6c"; status.textContent = d.detail || "Upload failed.";
  }
}

async function saveProfileName() {
  const name = document.getElementById("profile-display-name").value.trim();
  const status = document.getElementById("profile-status");
  if (!name) { status.style.color = "#e06c6c"; status.textContent = "Name required."; return; }
  status.style.color = "#888"; status.textContent = "Saving…";
  const r = await apiFetch("/api/profile", {
    method: "PUT",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({display_name: name}),
  });
  if (r.ok) {
    loadProfileAvatar();
    closeProfile();
  } else {
    status.style.color = "#e06c6c"; status.textContent = "Failed to save.";
  }
}

function copyPublicKey() {
  const key = document.getElementById("profile-pubkey").textContent;
  const msg = document.getElementById("profile-pubkey-copied");
  navigator.clipboard.writeText(key).then(() => {
    msg.textContent = "Copied!";
    setTimeout(() => { msg.textContent = ""; }, 2000);
  }).catch(() => {
    msg.style.color = "#e06c6c";
    msg.textContent = "Copy failed — select and copy manually.";
  });
}

async function uploadProfilePhoto(input) {
  const file = input.files[0];
  if (!file) return;
  const status = document.getElementById("profile-status");
  status.style.color = "#888"; status.textContent = "Uploading…";
  const fd = new FormData();
  fd.append("file", file);
  const r = await apiFetch("/api/profile/photo", {method: "PUT", body: fd});
  if (r.ok) {
    status.style.color = "#6dbf6d"; status.textContent = "Photo updated.";
    loadProfileAvatar();
    setTimeout(() => { status.textContent = ""; }, 2000);
  } else {
    status.style.color = "#e06c6c"; status.textContent = "Upload failed.";
  }
  input.value = "";
}

// ── setup / unlock ─────────────────────────────────────────────────────────

let _setupToken = null;
let _setupGoogleIdentity = null;
let _setupExistingOwnerId = null;
let restoreFile = null;

async function acceptSetupToken() {
  const token = document.getElementById("setup-token-input").value.trim();
  const err = document.getElementById("setup-token-error");
  if (!token) { err.textContent = "Token required."; return; }
  err.textContent = "Connecting…";
  try {
    const r = await fetch("/setup/identity-proxy-url");
    if (!r.ok) { err.textContent = "Could not reach server."; return; }
    const { url } = await r.json();
    const returnTo = window.location.origin + "/?setup_token=" + encodeURIComponent(token) + "&proxy_step=identity";
    window.location.href = url + "/auth/start?return_to=" + encodeURIComponent(returnTo);
  } catch { err.textContent = "Network error."; }
}

async function _handleSetupProxyIdentity(proxyToken, setupToken) {
  const err = document.getElementById("setup-token-error");
  err.textContent = "Verifying identity…";
  try {
    const r = await fetch("/setup/verify-proxy-identity?" + new URLSearchParams({proxy_token: proxyToken}));
    const d = await r.json();
    if (!r.ok) { err.textContent = d.detail || "Identity verification failed."; return; }
    _setupToken = setupToken;
    _setupGoogleIdentity = d.google_identity;
    _setupExistingOwnerId = d.owner_id;
    document.getElementById("setup-identity-display").textContent = d.google_identity.replace("google:", "");
    if (d.display_name) document.getElementById("setup-display-name").value = d.display_name;
    const ownerSection = document.getElementById("setup-owner-passphrase-section");
    ownerSection.hidden = d.is_new_owner;
    ownerSection.style.display = d.is_new_owner ? "" : "flex";
    document.getElementById("setup-submit-btn").textContent = d.is_new_owner ? "Create Identity" : "Add Node";
    err.textContent = "";
    document.getElementById("setup-token-step").hidden = true;
    document.getElementById("setup-wizard-step").hidden = false;
  } catch { err.textContent = "Network error."; }
}

function showSetupTab(tab) {
  document.getElementById("setup-new-form").hidden = tab !== "new";
  document.getElementById("setup-restore-form").hidden = tab !== "restore";
  document.getElementById("tab-new").classList.toggle("active", tab === "new");
  document.getElementById("tab-restore").classList.toggle("active", tab === "restore");
}

function restoreFileSelected(input) {
  restoreFile = input.files[0] || null;
  document.getElementById("restore-filename").textContent = restoreFile ? restoreFile.name : "";
}

function _badSetupToken(msg) {
  _setupToken = null;
  document.getElementById("setup-wizard-step").hidden = true;
  document.getElementById("setup-token-step").hidden = false;
  document.getElementById("setup-token-error").textContent = msg || "Invalid setup token.";
}


async function doSetupNew() {
  const displayName = document.getElementById("setup-display-name").value.trim();
  const handle = document.getElementById("setup-handle").value.trim().toLowerCase();
  const pass = document.getElementById("setup-passphrase").value;
  const confirm = document.getElementById("setup-passphrase-confirm").value;
  const err = document.getElementById("setup-new-error");
  err.textContent = "";
  if (!handle || !pass) { err.textContent = "All fields required."; return; }
  if (!/^[a-z_][a-z0-9_]*$/.test(handle)) { err.textContent = "Handle must start with a letter or _, followed by letters, digits, or _."; return; }
  if (pass !== confirm) { err.textContent = "Passphrases do not match."; return; }

  const baseBody = {passphrase: pass, confirm_passphrase: confirm, owner_identity: _setupGoogleIdentity,
    setup_token: _setupToken, handle, display_name: displayName,
    tang_enabled: document.getElementById("setup-tang").checked};

  if (_setupExistingOwnerId) {
    const ownerPass = document.getElementById("setup-owner-passphrase").value;
    if (!ownerPass) { err.textContent = "Owner passphrase required."; return; }
    try {
      const r = await fetch("/setup/new-for-owner", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({...baseBody, existing_owner_id: _setupExistingOwnerId, owner_passphrase: ownerPass}),
      });
      const d = await r.json();
      if (r.status === 403) { err.textContent = d.detail || "Wrong owner passphrase."; return; }
      if (!r.ok) { err.textContent = d.detail || "Error."; return; }
      if (d.client_session) setClientToken(d.client_session);
      location.reload();
    } catch { err.textContent = "Network error."; }
    return;
  }

  try {
    const r = await fetch("/setup/new", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(baseBody),
    });
    const d = await r.json();
    if (r.status === 403) { _badSetupToken(d.detail); return; }
    if (!r.ok) { err.textContent = d.detail || "Error."; return; }
    if (d.client_session) setClientToken(d.client_session);
    location.reload();
  } catch { err.textContent = "Network error."; }
}

function showIdentityManualPath() {
  document.getElementById("identity-escrow-section").hidden = true;
  document.getElementById("identity-manual-section").hidden = false;
}

function showIdentityEscrowPath() {
  document.getElementById("identity-manual-section").hidden = true;
  document.getElementById("identity-escrow-section").hidden = false;
}

async function uploadIdentityEscrowAndContinue() {
  const key = document.getElementById("identity-key-display").value.trim();
  const passphrase = document.getElementById("identity-owner-passphrase").value;
  const confirm = document.getElementById("identity-owner-passphrase-confirm").value;
  const status = document.getElementById("identity-escrow-status");
  const btn = document.getElementById("identity-escrow-btn");
  if (!passphrase) { status.textContent = "Enter a owner passphrase."; return; }
  if (passphrase !== confirm) { status.textContent = "Passphrases don't match."; return; }
  btn.disabled = true;
  status.textContent = "Uploading…";
  status.style.color = "#888";
  try {
    const r = await fetch("/setup/escrow-identity-key", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({identity_private_key: key, owner_passphrase: passphrase}),
    });
    if (r.ok) {
      location.reload();
    } else {
      const d = await r.json().catch(() => ({}));
      status.textContent = d.detail || "Upload failed.";
      status.style.color = "#e06c6c";
      btn.disabled = false;
    }
  } catch {
    status.textContent = "Network error.";
    status.style.color = "#e06c6c";
    btn.disabled = false;
  }
}

async function doSetupRestore() {
  const pass = document.getElementById("restore-passphrase").value;
  const err = document.getElementById("setup-restore-error");
  err.textContent = "";
  if (!restoreFile) { err.textContent = "Please select a backup file."; return; }
  if (!pass) { err.textContent = "Passphrase required."; return; }
  const fd = new FormData();
  fd.append("bundle", restoreFile);
  fd.append("passphrase", pass);
  fd.append("setup_token", _setupToken || "");
  try {
    const r = await fetch("/setup/restore", {method: "POST", body: fd});
    const d = await r.json();
    if (r.status === 403) { _badSetupToken(d.detail); return; }
    if (!r.ok) { err.textContent = d.detail || "Error."; return; }
    location.reload();
  } catch { err.textContent = "Network error."; }
}

async function doUnlock() {
  const pass = document.getElementById("unlock-passphrase").value;
  const err = document.getElementById("unlock-error");
  err.textContent = "";
  try {
    const r = await fetch("/setup/unlock", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({passphrase: pass}),
    });
    const d = await r.json();
    if (!r.ok) { err.textContent = d.detail || "Wrong passphrase."; return; }
    location.reload();
  } catch { err.textContent = "Network error."; }
}

