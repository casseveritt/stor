// ── state ──────────────────────────────────────────────────────────────────
let CFG = null;
function _setCFG(cfg) {
  CFG = cfg;
  if (cfg?.own_display_name || cfg?.own_handle) {
    if (!serverProfiles[cfg.own_server]?.display_name) {
      serverProfiles[cfg.own_server] = { display_name: cfg.own_display_name, handle: cfg.own_handle };
    }
  }
}
let activeServer = null;
let activeTags = new Set();
let allPosts = [];
let currentIdx = -1; // used by openEdit only
let nextCursor = null, currentSearch = null, searchTimer = null;
let pendingFiles = [];
let IS_OWNER = false;
let serverStatuses = {};
let serverOnline = {};  // server_url → boolean, from server_status in feed response
let serverHandles = {};
let serverProfiles = {};
let serverPublicKeys = {}; // base64 pubkey → server url
let _keyToProfile = {};   // base64 pubkey → {username, display_name} from registry
let _pendingKeyLookups = new Set();

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
        const urlToken = new URLSearchParams(location.search).get("setup_token");
        if (urlToken) {
          document.getElementById("setup-token-input").value = urlToken;
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


async function logout() {
  await apiFetch("/api/auth/token", {method: "DELETE"});
  clearClientToken();
  CFG = null;
  location.reload();
}

async function loadIdentity() {
  const r = await apiFetch("/api/auth/me");
  if (!r.ok) return;
  const d = await r.json();
  IS_OWNER = d.role === "owner";
  document.getElementById("compose-btn").hidden = !IS_OWNER;
  document.getElementById("dev-menu-wrap").style.display = (CFG?.dev && IS_OWNER) ? '' : 'none';
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
  document.getElementById("setup-view").hidden  = name !== "setup";
  document.getElementById("unlock-view").hidden = name !== "unlock";
  document.getElementById("login-view").hidden  = name !== "login";
  document.getElementById("feed-view").hidden   = name !== "feed";
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
    const urlJson = JSON.stringify(s.url).replace(/"/g, '&quot;');
    const tagJson = JSON.stringify(s.tag || '').replace(/"/g, '&quot;');
    return '<div class="contact-row">'
      + '<button class="server-btn' + (activeServer === s.url ? " active" : "") + '" onclick="setActiveServer(' + globalIdx + ')" title="' + esc(tagLabel ? '@' + tagLabel : s.name) + '">'
      + avatarHtml
      + '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + label + '</span>'
      + '<span class="server-dot ' + status + '"></span>'
      + '</button>'
      + '<span style="position:relative;display:inline-flex;align-items:center">'
      + '<button class="contact-menu-btn" onclick="openContactMenu(event,' + urlJson + ',' + tagJson + ')" title="Contact options">…</button>'
      + '</span>'
      + '</div>';
  });
  list.innerHTML = allBtn + serverBtns.join("");
}

function openContactMenu(e, url, tag) {
  e.stopPropagation();
  closeAllPostMenus();
  const btn = e.currentTarget;
  const wrap = btn.parentElement;
  const popup = document.createElement('div');
  popup.className = 'post-menu-popup';
  const tagBtn = document.createElement('button');
  tagBtn.textContent = 'Set @tag';
  tagBtn.onclick = () => { closeAllPostMenus(); setContactTag(url, tag); };
  const removeBtn = document.createElement('button');
  removeBtn.className = 'danger';
  removeBtn.textContent = 'Remove';
  removeBtn.onclick = () => { closeAllPostMenus(); removeContact(url); };
  popup.appendChild(tagBtn);
  popup.appendChild(removeBtn);
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
  document.querySelectorAll('.comment-author[data-identity]').forEach(el => {
    const identity = el.dataset.identity;
    const serverUrl = el.dataset.server || CFG.own_server;
    const au = _commentAuthor(identity, serverUrl);
    el.querySelector('.comment-author-name').textContent = au.name;
  });
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
        const activity7d = (d.posts_7d || 0) + (d.comments_7d || 0);
        _serverPollIntervals[s.url] = _computePollInterval(activity7d);
      }
    } catch {}
  }
}

async function fetchServerProfiles() {
  const servers = [CFG.own_server, ...(CFG.contacts || []).map(c => c.url)];
  // Seed from server (authoritative — knows what's actually on disk) + localStorage
  const cachedPhotos = new Set([...(CFG.cached_photos || []), ...JSON.parse(localStorage.getItem('cachedContactPhotos') || '[]')]);

  // Pre-seed contacts from local config so names show even when offline;
  // only set photo_url if we've previously confirmed a cached photo exists.
  for (const c of (CFG.contacts || [])) {
    if (!serverProfiles[c.url]) {
      serverProfiles[c.url] = {
        display_name: c.name,
        handle: c.handle,
        photo_url: cachedPhotos.has(c.url) ? "/api/contacts/photo?url=" + encodeURIComponent(c.url) : null,
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
          const proxyUrl = "/api/contacts/photo?url=" + encodeURIComponent(url);
          if (profile.photo_url) {
            fetch(proxyUrl).catch(() => {}); // warm the cache
            profile.photo_url = proxyUrl;
            if (!cachedPhotos.has(url)) {
              cachedPhotos.add(url);
              localStorage.setItem('cachedContactPhotos', JSON.stringify([...cachedPhotos]));
            }
          } else {
            if (cachedPhotos.has(url)) {
              cachedPhotos.delete(url);
              localStorage.setItem('cachedContactPhotos', JSON.stringify([...cachedPhotos]));
            }
            profile.photo_url = null;
          }
        }
        serverProfiles[url] = profile;
        serverStatuses[url] = "ok";
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
    body: JSON.stringify({name, url: _pendingContact.server_url, handle: _pendingContact.handle || null, public_key: _pendingContact.public_key || null}),
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
  const r = await apiFetch("/api/tags");
  if (!r.ok) return;
  const data = await r.json();
  const list = document.getElementById("tag-list");
  list.innerHTML = (data.tags || []).map(({tag, count}) =>
    '<button class="tag-btn' + (activeTags.has(tag) ? " active" : "") + '" onclick="toggleTag(\'' + esc(tag) + '\')">'
    + '<span>' + esc(tag) + '</span><span class="tc">' + count + '</span></button>'
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

  // Auth check — redirect to login if unauthenticated.
  const authCheck = await apiFetch("/api/feed?limit=1");
  if (authCheck.status === 401) { showView("login"); return false; }

  loadIdentity();
  loadTagSidebar();
  fetchServerHandles().then(() => _startBgFetch());
  fetchServerProfiles();

  if (allPosts.length === 0) {
    // No cache — block until we have something to show.
    const ok = await resetFeed(true);
    if (!ok) { showView("login"); return false; }
  } else {
    // Cache is warm — let the UI settle, then refresh from servers in the background.
    const servers = activeServer ? [activeServer] : [CFG.own_server, ...(CFG.contacts || []).map(c => c.url)];
    for (const url of servers) _serverLastFetched[url] = 0;
    setTimeout(async () => {
      await _runBgFetch();
      const el = document.getElementById("feed-status");
      if (el && el.textContent.includes('refreshing')) {
        const n = allPosts.length;
        el.textContent = n ? n + " post" + (n !== 1 ? "s" : "") : "";
      }
    }, 3000);
  }

  return true;
}

async function resetFeed(allowLoginRedirect = false) {
  nextCursor = null; allPosts = []; currentIdx = -1;
  document.getElementById("timeline").innerHTML = "";
  document.getElementById("empty-msg").hidden = true;
  document.getElementById("feed-status").textContent = "";
  document.getElementById("new-posts-banner").hidden = true;
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
      serverOnline[url] = status === "online";
    }
  }
  renderServerList();

  const timeline = document.getElementById("timeline");
  for (const post of data.posts) {
    allPosts.push(post);
    timeline.appendChild(makePostCard(post, allPosts.length - 1));
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
    const c = (CFG?.contacts || []).find(c => c.public_key === id);
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
  const btn = e.target.closest('.reaction-add');
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

function reactionBarHtml(reactions, postId, serverUrl, commentId) {
  const cid = commentId || '';
  const btns = (reactions || []).map(r => {
    const cls = r.reacted ? 'reaction-btn reacted' : 'reaction-btn';
    const reactorsJson = esc(JSON.stringify(r.reactors || []));
    return `<button class="${cls}" data-reactors="${reactorsJson}" data-server="${esc(serverUrl)}" onmouseenter="_showReactorTooltip(event,this)" onmouseleave="_hideReactorTooltip()" onclick="event.stopPropagation();toggleReaction('${esc(postId)}','${esc(serverUrl)}','${r.emoji}','${esc(cid)}',this)">${r.emoji} <span>${r.count}</span></button>`;
  }).join('');
  const add = `<button class="reaction-add" onclick="if(_longPressActivated){_longPressActivated=false;}else{event.stopPropagation();showEmojiPicker(event,'${esc(postId)}','${esc(serverUrl)}','${esc(cid)}')}" title="Add reaction • hold to see all reactions">+</button>`;
  return `<div class="reaction-bar" data-post-id="${esc(postId)}" data-server="${esc(serverUrl)}" data-comment-id="${esc(cid)}">${btns}${add}</div>`;
}

function showEmojiPicker(event, postId, serverUrl, commentId) {
  document.querySelectorAll('.emoji-picker').forEach(p => p.remove());
  const bar = event.target.closest('.reaction-bar');
  if (!bar) return;
  const picker = document.createElement('div');
  picker.className = 'emoji-picker';
  for (const emoji of REACTION_EMOJI) {
    const b = document.createElement('button');
    b.className = 'emoji-pick-btn';
    b.textContent = emoji;
    b.onclick = e => { e.stopPropagation(); picker.remove(); toggleReaction(postId, serverUrl, emoji, commentId, null); };
    picker.appendChild(b);
  }
  bar.insertAdjacentElement('afterend', picker);
  setTimeout(() => document.addEventListener('click', function close() {
    picker.remove(); document.removeEventListener('click', close);
  }, {once: true}), 0);
}

async function toggleReaction(postId, serverUrl, emoji, commentId, _btn) {
  const params = serverUrl !== CFG.own_server ? '?server=' + encodeURIComponent(serverUrl) : '';
  const r = await apiFetch('/api/posts/' + postId + '/react' + params, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({emoji, comment_id: commentId || ''}),
  });
  if (!r.ok) return;
  const data = await r.json();
  const cid = commentId || '';
  document.querySelectorAll(`.reaction-bar[data-post-id="${postId}"][data-comment-id="${cid}"]`).forEach(bar => {
    const tmp = document.createElement('div');
    tmp.innerHTML = reactionBarHtml(data.reactions, postId, serverUrl, cid);
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
  return post._is_cached || serverOnline[post._server_url] === false;
}

function makePostCard(post, idx) {
  const div = document.createElement("div");
  div.className = "post-card" + (_isPostCached(post) ? " post-cached" : "");
  div.dataset.idx = idx;
  div.dataset.postId = post.id;

  const author = document.createElement("div");
  author.className = "post-author";
  author.dataset.server = post._server_url;
  _renderAuthorInto(author, post._server_url);
  const dateFmt = post.created_at ? new Date(post.created_at * 1000).toLocaleDateString() : "";
  const rightGroup = document.createElement("span");
  rightGroup.style.cssText = "display:inline-flex;align-items:center;gap:0.35rem;flex-shrink:0";
  rightGroup.className = "post-author-right";
  rightGroup.innerHTML = (dateFmt ? `<span class="post-date">${dateFmt}</span>` : '')
    + _levelIconHtml(post.visibility, post.visibility)
    + `<span style="position:relative;display:inline-flex;align-items:center">`
    + `<button class="post-menu-btn" title="More options" onclick="openPostMenu(event,${idx},'${esc(post.id)}','${esc(post._server_url||'')}')">…</button>`
    + `</span>`;
  author.appendChild(rightGroup);
  div.appendChild(author);

  const bodyText = (post.body || "").replace(/\[asset:[0-9a-f-]+\]/g, "").trim();
  if (bodyText) {
    const p = document.createElement("div");
    p.className = "post-body";
    p.innerHTML = _renderMentions(bodyText);
    div.appendChild(p);
  }

  if (post.assets && post.assets.length) {
    const strip = document.createElement("div");
    strip.className = "post-thumbs";
    for (const asset of post.assets) {
      if ((asset.media_type || "").startsWith("image/")) {
        const img = document.createElement("img");
        img.className = "post-thumb loading";
        img.onload = img.onerror = () => img.classList.remove("loading");
        img.alt = ""; img.loading = "lazy";
        const params = post._server_url !== CFG.own_server
          ? "?server=" + encodeURIComponent(post._server_url) : "";
        const thumbBase = "/api/assets/" + asset.id + "/thumb" + params + clientTokenParam(!!params);
        const hashQ = asset.content_hash ? (thumbBase.includes('?') ? '&' : '?') + 'hash=' + encodeURIComponent(asset.content_hash) : '';
        img.src = thumbBase + hashQ;
        const fullBase = "/api/assets/" + asset.id + params + clientTokenParam(!!params);
        const fullSrc = fullBase + (asset.content_hash ? (fullBase.includes('?') ? '&' : '?') + 'hash=' + encodeURIComponent(asset.content_hash) : '');
        img.onclick = () => openLightbox(fullSrc);
        strip.appendChild(img);
      } else {
        const ic = document.createElement("div");
        ic.className = "post-thumb-icon";
        ic.textContent = mimeIcon(asset.media_type);
        strip.appendChild(ic);
      }
    }
    div.appendChild(strip);
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
  rbarWrap.innerHTML = reactionBarHtml(post.reactions || [], post.id, post._server_url, '');
  div.appendChild(rbarWrap.firstChild);

  // comments toggle
  const count = post.comment_count || 0;
  const toggle = document.createElement("div");
  toggle.className = "comments-toggle";
  toggle.dataset.postId = post.id;
  const commentIconHtml = _levelIconHtml(post.comment_access, 'comments: ' + (post.comment_access || 'contacts'));
  toggle.innerHTML = '<span style="display:inline-flex;align-items:center;gap:0.35rem"><span class="comments-toggle-arrow">▶</span><span class="comments-toggle-label">'
    + count + ' comment' + (count !== 1 ? 's' : '') + '</span></span>' + commentIconHtml;
  toggle.onclick = () => _toggleComments(post, div);
  div.appendChild(toggle);

  const panel = document.createElement("div");
  panel.className = "comments-panel";
  panel.dataset.postId = post.id;
  panel.hidden = true;
  div.appendChild(panel);

  return div;
}

// ── keyboard nav ───────────────────────────────────────────────────────────
document.addEventListener("keydown", e => {
  if (e.key === "Escape") closeAllPostMenus();
  if (!document.getElementById("lightbox").hidden && e.key === "Escape") closeLightbox();
  if (!document.getElementById("compose-overlay").hidden && e.key === "Escape") closeCompose();
  if (!document.getElementById("edit-overlay").hidden && e.key === "Escape") closeEdit();
  if (!document.getElementById("profile-overlay").hidden && e.key === "Escape") closeProfile();
  if (!document.getElementById("add-contact-overlay").hidden && e.key === "Escape") closeAddContact();
});

function renderPostBody(post) {
  const assetMap = {};
  for (const a of (post.assets || [])) assetMap[a.id] = a;
  const parts = (post.body || "").split(/(\[asset:[0-9a-f-]+\])/);
  let rendered = "";
  for (const part of parts) {
    const m = part.match(/^\[asset:([0-9a-f-]+)\]$/);
    if (m) {
      const aid = m[1], a = assetMap[aid];
      const params = post._server_url !== CFG.own_server
        ? "?server=" + encodeURIComponent(post._server_url) : "";
      const url = "/api/assets/" + aid + params + clientTokenParam(!!params);
      if (a && (a.media_type || "").startsWith("image/"))
        rendered += '<span class="asset-block"><img src="' + url + '" alt="" onclick="openLightbox(this.src)"></span>';
      else if (a && (a.media_type || "").startsWith("video/"))
        rendered += '<span class="asset-block"><video src="' + url + '" controls></video></span>';
      else {
        const label = (a && a.title) ? a.title : aid.slice(0, 8) + "…";
        rendered += '<span class="asset-block"><a class="asset-file" href="' + url + '" download>' + mimeIcon(a && a.media_type) + ' ' + esc(label) + '</a></span>';
      }
    } else { rendered += _renderMentions(part); }
  }
  return rendered;
}

// ── polling ────────────────────────────────────────────────────────────────
const POLL_DETAIL_MS    = 20_000;
const BG_CHECK_MS       = 60_000;   // how often the scheduler wakes to check due servers
const DEFAULT_POLL_MS   = 30 * 60_000;
const MIN_POLL_MS       =  5 * 60_000;
const MAX_POLL_MS       = 60 * 60_000;

let _detailPollTimer  = null;
let _bgFetchTimer     = null;
let _serverLastFetched  = {};     // url → ms timestamp of last successful fetch
let _serverPollIntervals = {};    // url → ms (computed from node activity)
const _openPanels = new Map();    // postId → post
let _newestKnownAt = 0;           // created_at of newest post we've ever seen; survives allPosts = []

function _computePollInterval(activity7d) {
  if (!activity7d) return MAX_POLL_MS;
  const perDay = activity7d / 7;
  return Math.max(MIN_POLL_MS, Math.min(MAX_POLL_MS, Math.round(30 * 60_000 / perDay)));
}

function _startDetailPoll() {
  clearInterval(_detailPollTimer);
  if (_openPanels.size === 0) return;
  _detailPollTimer = setInterval(_pollOpenPanels, POLL_DETAIL_MS);
}
function _stopDetailPoll() {
  clearInterval(_detailPollTimer); _detailPollTimer = null;
}
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
    const panel = document.querySelector(`.comments-panel[data-post-id="${postId}"]`);
    if (!panel || panel.hidden) continue;
    _loadCommentsIntoPanel(post, panel);
    const params = post._server_url !== CFG.own_server ? '?server=' + encodeURIComponent(post._server_url) : '';
    const r = await apiFetch('/api/posts/' + postId + params);
    if (!r.ok) continue;
    const updated = await r.json();
    if (!updated.reactions) continue;
    post.reactions = updated.reactions;
    document.querySelectorAll(`.reaction-bar[data-post-id="${postId}"][data-comment-id=""]`).forEach(bar => {
      const tmp = document.createElement('div');
      tmp.innerHTML = reactionBarHtml(updated.reactions, postId, post._server_url, '');
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
    if (post) { post.comment_count = updated.comment_count; post.reactions = updated.reactions; post.body = updated.body; }
    const panel = card.querySelector('.comments-panel');
    const toggle = card.querySelector('.comments-toggle');
    if (panel?.hidden && toggle) {
      const count = updated.comment_count || 0;
      toggle.querySelector('.comments-toggle-label').textContent = count + ' comment' + (count !== 1 ? 's' : '');
    }
    if (updated.reactions) {
      const serverUrl = post?._server_url || CFG.own_server;
      card.querySelectorAll(`.reaction-bar[data-post-id="${updated.id}"][data-comment-id=""]`).forEach(bar => {
        const tmp = document.createElement('div');
        tmp.innerHTML = reactionBarHtml(updated.reactions, updated.id, serverUrl, '');
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

  for (const p of freshPosts) { if (p.created_at > newestTs) newCount++; }
  if (freshPosts.length > 0) _newestKnownAt = Math.max(_newestKnownAt, freshPosts[0].created_at || 0);
  if (newCount > 0) {
    const banner = document.getElementById('new-posts-banner');
    banner.textContent = 'New posts available — click to refresh';
    banner.hidden = false;
  }
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
  const now = Date.now();
  const servers = activeServer ? [activeServer] : [CFG.own_server, ...(CFG.contacts || []).map(c => c.url)];
  await Promise.all(servers.map(async url => {
    const interval = _serverPollIntervals[url] || DEFAULT_POLL_MS;
    if (now - (_serverLastFetched[url] || 0) >= interval) await _fetchOneServer(url);
  }));
}

function refreshFeed() {
  document.getElementById('new-posts-banner').hidden = true;
  resetFeed();
}

// ── inline comments toggle ─────────────────────────────────────────────────
function _toggleComments(post, cardEl) {
  const panel = cardEl.querySelector('.comments-panel');
  const toggle = cardEl.querySelector('.comments-toggle');
  const arrow = toggle.querySelector('.comments-toggle-arrow');
  const label = toggle.querySelector('.comments-toggle-label');
  if (panel.hidden) {
    panel.hidden = false;
    arrow.textContent = '▼';
    label.textContent = 'Loading comments…';
    _openPanels.set(post.id, post);
    _startDetailPoll();
    _loadCommentsIntoPanel(post, panel);
  } else {
    panel.hidden = true;
    arrow.textContent = '▶';
    const count = post.comment_count || 0;
    label.textContent = count + ' comment' + (count !== 1 ? 's' : '');
    _openPanels.delete(post.id);
    if (_openPanels.size === 0) _stopDetailPoll();
  }
}

// ── comments ───────────────────────────────────────────────────────────────
async function _loadCommentsIntoPanel(post, panel) {
  const params = post._server_url !== CFG.own_server
    ? "?server=" + encodeURIComponent(post._server_url) : "";
  const r = await apiFetch("/api/posts/" + post.id + "/comments" + params);
  if (!panel.isConnected || panel.hidden) return;
  if (!r.ok) { panel.innerHTML = ""; return; }
  const data = await r.json();
  _renderCommentsInto(post, data.comments, panel);
  // update toggle label with live count
  const toggle = panel.previousElementSibling;
  if (toggle?.classList.contains('comments-toggle')) {
    const live = data.comments.filter(c => !c.deleted).length;
    post.comment_count = live;
    toggle.querySelector('.comments-toggle-label').textContent = live + ' comment' + (live !== 1 ? 's' : '');
  }
}

function _commentAuthor(identity, postServerUrl) {
  return _resolveIdentity(identity, postServerUrl);
}

function _renderCommentsInto(post, comments, panel) {
  const live = comments.filter(c => !c.deleted);
  const byParent = {};
  for (const c of live) { const k = c.parent_id || "__root__"; (byParent[k] = byParent[k] || []).push(c); }
  function renderOne(c, depth) {
    const replies = byParent[c.id] || [];
    const au = _commentAuthor(c.author_identity, post._server_url);
    const avatar = au.photoUrl
      ? `<img src="${esc(au.photoUrl)}" class="post-author-avatar" alt="">`
      : `<span class="post-author-initials">${esc((au.name[0]||'?').toUpperCase())}</span>`;
    const identityAttr = c.author_identity ? ` data-identity="${esc(c.author_identity)}" data-server="${esc(post._server_url || '')}"` : '';
    const dateFmt = fmtDate(c.created_at);
    const isOwnComment = IS_OWNER && post._server_url === CFG.own_server && (!c.author_identity || c.author_identity === '');
    const menuBtn = `<span style="position:relative;display:inline-flex;align-items:center"><button class="post-menu-btn" title="More options" onclick="openCommentMenu(event,'${esc(post.id)}','${esc(post._server_url)}','${esc(c.id)}',${isOwnComment})">…</button></span>`;
    return '<div class="comment" data-comment-id="' + esc(c.id) + '">'
      + `<div class="comment-author"${identityAttr}>`
      + `<span style="display:inline-flex;align-items:center;gap:0.4rem">` + avatar + `<span class="comment-author-name">${esc(au.name)}</span></span>`
      + `<span style="display:inline-flex;align-items:center;gap:0.35rem;flex-shrink:0">`
      + (dateFmt ? `<span class="post-date">${dateFmt}</span>` : '')
      + menuBtn + `</span>`
      + `</div>`
      + '<div class="comment-body">' + _renderMentions(c.body || '') + '</div>'
      + reactionBarHtml(c.reactions || [], post.id, post._server_url, c.id)
      + (replies.length ? '<div class="comment-replies">' + replies.map(r => renderOne(r, depth+1)).join("") + '</div>' : '')
      + '</div>';
  }
  const roots = byParent["__root__"] || [];
  panel.innerHTML =
    roots.map(c => renderOne(c, 0)).join("")
    + '<div class="comment-form">'
    + '<textarea class="comment-input" data-post-id="' + esc(post.id) + '" placeholder="Add a comment…"></textarea>'
    + '<div class="comment-form-actions"><button class="btn btn-primary btn-sm" onclick="submitComment(\'' + esc(post.id) + '\',\'' + esc(post._server_url) + '\')">Post</button>'
    + '<span class="comment-error" data-post-id="' + esc(post.id) + '" style="color:#e06c6c;font-size:0.82rem"></span></div>'
    + '</div>';
}

async function submitComment(postId, serverUrl) {
  const input = document.querySelector('.comment-input[data-post-id="' + postId + '"]');
  const body = input ? _expandMentions(input.value.trim()) : "";
  if (!body) return;
  const params = serverUrl !== CFG.own_server ? "?server=" + encodeURIComponent(serverUrl) : "";
  const r = await apiFetch("/api/posts/" + postId + "/comments" + params, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({body}),
  });
  if (r.ok) {
    if (input) input.value = "";
    const post = _openPanels.get(postId);
    const panel = document.querySelector(`.comments-panel[data-post-id="${postId}"]`);
    if (post && panel) _loadCommentsIntoPanel(post, panel);
  } else {
    const errEl = document.querySelector('.comment-error[data-post-id="' + postId + '"]');
    if (errEl) errEl.textContent = r.status === 403 ? "Access denied." : "Failed to post comment.";
  }
}

// ── @mention autocomplete ──────────────────────────────────────────────────
let _mentionState = null;
const COMPOSE_CTX = { taId: 'compose-body', hlId: 'compose-highlight', ddId: 'compose-mention-dropdown' };
const EDIT_CTX    = { taId: 'edit-body',    hlId: 'edit-highlight',    ddId: 'edit-mention-dropdown' };

// Event delegation for comment inputs — assign a stable id and switch context on first input.
document.addEventListener('input', e => {
  const ta = e.target;
  if (!ta.classList.contains('comment-input')) return;
  if (!ta.id) ta.id = 'comment-ta-' + ta.dataset.postId;
  _mentionCtx = { taId: ta.id, hlId: null, ddId: 'comment-mention-dropdown' };
  onComposeInput();
  _repositionCommentDropdown(ta);
}, true);
document.addEventListener('keydown', e => {
  if (!e.target.classList.contains('comment-input')) return;
  if (!e.target.id) return;
  _mentionCtx = { taId: e.target.id, hlId: null, ddId: 'comment-mention-dropdown' };
  onComposeKeydown(e);
}, true);
document.addEventListener('blur', e => {
  if (e.target.classList.contains('comment-input'))
    setTimeout(hideMentionDropdown, 150);
}, true);

function _repositionCommentDropdown(ta) {
  const dd = document.getElementById('comment-mention-dropdown');
  if (!dd || dd.hidden) return;
  const r = ta.getBoundingClientRect();
  const left = Math.min(r.left, window.innerWidth - dd.offsetWidth - 8);
  dd.style.top  = (r.bottom + 2) + 'px';
  dd.style.left = Math.max(4, left) + 'px';
}
let _mentionCtx = COMPOSE_CTX;

function _contactTag(c) {
  const displayName = (serverProfiles[c.url] || {}).display_name || c.name;
  return c.tag || displayName.trim().split(/\s+/)[0] || c.handle || 'contact';
}

function _mentionTag(c) {
  return '@' + _contactTag(c);
}

// Expand @tag → [pubkey|tag] for known contacts. Called at submit time.
function _expandMentions(text) {
  const tagMap = new Map();
  for (const c of (CFG?.contacts || [])) {
    if (!c.public_key) continue;
    const tag = _contactTag(c);
    tagMap.set(tag.toLowerCase(), {label: tag, pubkey: c.public_key});
  }
  return text.replace(/@(\w+)/g, (full, word) => {
    const entry = tagMap.get(word.toLowerCase());
    return entry ? `[${entry.pubkey}|${entry.label}]` : full;
  });
}

// Collapse [pubkey|disptext] → @tag (reader's current tag for that pubkey). Called when loading for edit.
function _collapseMentions(text) {
  return text.replace(/\[([^|\]]+)\|([^\]]+)\]/g, (full, pubkey, disptext) => {
    const contact = (CFG?.contacts || []).find(c => c.public_key === pubkey);
    return `@${contact ? _contactTag(contact) : disptext}`;
  });
}

// Render [pubkey|disptext] tokens in a post body as styled mention spans.
// Uses the stored disptext as the label; tooltip shows the contact's display name.
function _renderMentions(text) {
  return text.split(/(\[[^\]]+\])/).map(part => {
    const m = part.match(/^\[([^|\]]+)\|([^\]]+)\]$/);
    if (!m) return esc(part);
    const pubkey = m[1], disptext = m[2];
    const contact = (CFG?.contacts || []).find(c => c.public_key === pubkey);
    const prof = contact ? (serverProfiles[contact.url] || {}) : {};
    const tooltip = prof.display_name || (contact ? contact.name : disptext);
    return `<span class="mention-tag" title="${esc(tooltip)}">${esc(disptext)}</span>`;
  }).join('');
}

function onComposeInput() {
  _updateHighlight();
  const ta = document.getElementById(_mentionCtx.taId);
  const pos = ta.selectionStart;
  const before = ta.value.substring(0, pos);
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
  document.getElementById(_mentionCtx.ddId).hidden = true;
  _mentionState = null;
}

function _selectMention(c) {
  const state = _mentionState;
  if (!state) return;
  const ta = document.getElementById(_mentionCtx.taId);
  const label = _contactTag(c);
  // Replace @query (state.start points to the @) with [pubkey|label] — consuming the @
  const replacement = c.public_key ? `[${c.public_key}|${label}] ` : `@${label} `;
  const before = ta.value.substring(0, state.start);
  // Use the known end of "@query" from state rather than ta.selectionStart,
  // which can be wrong if focus shifted momentarily during the click.
  const mentionEnd = state.start + 1 + state.query.length;
  const after = ta.value.substring(mentionEnd);
  ta.value = before + replacement + after;
  const p = before.length + replacement.length;
  ta.selectionStart = ta.selectionEnd = p;
  hideMentionDropdown();
  _updateHighlight();
  ta.focus();
}

function onComposeKeydown(e) {
  if (!_mentionState) return;
  const items = document.getElementById(_mentionCtx.ddId).querySelectorAll('.mention-item');
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
  const knownPubkeys = new Set((CFG?.contacts || []).map(c => c.public_key).filter(Boolean));
  const escaped = ta.value
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const highlighted = escaped
    .replace(/\[([^|\]]*)\|([^\]]*)\]/g, (full, pubkey, disptext) => {
      return knownPubkeys.has(pubkey)
        ? `<span class="mention-dim">[${pubkey}|</span>${disptext}<span class="mention-dim">]</span>`
        : full;
    });
  if (hl) { hl.innerHTML = highlighted + '​'; hl.scrollTop = ta.scrollTop; }
}

// ── compose ────────────────────────────────────────────────────────────────
function openCompose() {
  _mentionCtx = COMPOSE_CTX;
  pendingFiles = [];
  document.getElementById("compose-body").value = "";
  _updateHighlight();
  document.getElementById("compose-tags").value = "";
  document.getElementById("compose-visibility").value = "contacts";
  document.getElementById("compose-comment-access").value = "contacts";
  document.getElementById("compose-progress").innerHTML = "";
  document.getElementById("compose-submit").disabled = false;
  document.getElementById("file-list").innerHTML = "";
  document.getElementById("compose-overlay").hidden = false;
  document.getElementById("compose-body").focus();
}
function closeCompose() { hideMentionDropdown(); document.getElementById("compose-overlay").hidden = true; }
function dzOver(e) { e.preventDefault(); document.getElementById("drop-zone").classList.add("over"); }
function dzOut()   { document.getElementById("drop-zone").classList.remove("over"); }
function dzDrop(e) { e.preventDefault(); dzOut(); addFiles(e.dataTransfer.files); }
function pickFiles(files) { addFiles(files); }
function addFiles(files) {
  for (const f of files) pendingFiles.push(f);
  document.getElementById("file-list").innerHTML = pendingFiles.map(f =>
    '<div class="file-item"><span>' + esc(f.name) + '</span><span>' + fmtSize(f.size) + '</span></div>'
  ).join("");
}

async function submitPost() {
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
  fd.append("comment_access", document.getElementById("compose-comment-access").value);
  for (const f of pendingFiles) fd.append("files", f);

  try {
    const r = await apiFetch("/api/posts", {method: "POST", body: fd});
    if (r.ok) {
      const post = await r.json();
      prependPost(post);
      loadTagSidebar();
      prog.innerHTML = '<div class="progress-item progress-ok">&#x2713; Posted</div>';
      pendingFiles = [];
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
  timeline.insertBefore(makePostCard(post, 0), timeline.firstChild);
  document.getElementById("empty-msg").hidden = true;
}

// ── post context menu ──────────────────────────────────────────────────────
function closeAllPostMenus() {
  document.querySelectorAll('.post-menu-popup').forEach(m => m.remove());
}

function openPostMenu(e, idx, postId, serverUrl) {
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

// ── comment context menu ───────────────────────────────────────────────────
function openCommentMenu(e, postId, serverUrl, commentId, isOwn) {
  e.stopPropagation();
  closeAllPostMenus();
  const btn = e.currentTarget;
  const wrap = btn.parentElement;
  const popup = document.createElement('div');
  popup.className = 'post-menu-popup';
  if (isOwn) {
    popup.innerHTML =
      `<button onclick="closeAllPostMenus();editCommentInline('${esc(postId)}','${esc(serverUrl)}','${esc(commentId)}')">Edit</button>`
      + `<button class="danger" onclick="closeAllPostMenus();deleteComment('${esc(postId)}','${esc(serverUrl)}','${esc(commentId)}')">Delete</button>`;
  }
  wrap.appendChild(popup);
  const dismiss = ev => { if (!popup.contains(ev.target) && ev.target !== btn) { closeAllPostMenus(); document.removeEventListener('click', dismiss, true); } };
  setTimeout(() => document.addEventListener('click', dismiss, true), 0);
}

function editCommentInline(postId, serverUrl, commentId) {
  const commentEl = document.querySelector('.comment[data-comment-id="' + commentId + '"]');
  if (!commentEl) return;
  const bodyEl = commentEl.querySelector('.comment-body');
  if (!bodyEl) return;
  const original = bodyEl.textContent;
  const ta = document.createElement('textarea');
  ta.value = original;
  ta.style.cssText = 'width:100%;background:#222;color:#e0e0e0;border:1px solid #4285f4;border-radius:4px;padding:0.4rem;font-size:0.88rem;resize:vertical;min-height:60px;outline:none;font-family:inherit;box-sizing:border-box';
  const actions = document.createElement('div');
  actions.style.cssText = 'display:flex;gap:0.5rem;justify-content:flex-end;margin-top:0.3rem';
  const saveBtn = document.createElement('button');
  saveBtn.className = 'btn btn-primary btn-sm';
  saveBtn.textContent = 'Save';
  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'btn btn-muted btn-sm';
  cancelBtn.textContent = 'Cancel';
  actions.appendChild(cancelBtn);
  actions.appendChild(saveBtn);
  bodyEl.replaceWith(ta);
  ta.after(actions);
  ta.focus();
  cancelBtn.onclick = () => { actions.remove(); ta.replaceWith(bodyEl); };
  saveBtn.onclick = async () => {
    const newBody = ta.value.trim();
    if (!newBody) return;
    saveBtn.disabled = true;
    const r = await apiFetch('/api/posts/' + postId + '/comments/' + commentId, {
      method: 'PATCH', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({body: newBody}),
    });
    if (r.ok) {
      bodyEl.textContent = newBody;
      actions.remove();
      ta.replaceWith(bodyEl);
    } else {
      saveBtn.disabled = false;
    }
  };
}

async function deleteComment(postId, serverUrl, commentId) {
  if (!confirm('Delete this comment?')) return;
  const r = await apiFetch('/api/posts/' + postId + '/comments/' + commentId, {method: 'DELETE'});
  if (r.ok || r.status === 204) {
    const commentEl = document.querySelector('.comment[data-comment-id="' + commentId + '"]');
    if (commentEl) commentEl.remove();
    const post = allPosts.find(p => p.id === postId);
    if (post) {
      post.comment_count = Math.max(0, (post.comment_count || 1) - 1);
      const toggle = document.querySelector('.comments-toggle[data-post-id="' + postId + '"] .comments-toggle-label');
      if (toggle) { const n = post.comment_count; toggle.textContent = n + ' comment' + (n !== 1 ? 's' : ''); }
    }
  }
}

// ── edit / delete ──────────────────────────────────────────────────────────
let editingIdx = -1;

function openEdit(idx) {
  _mentionCtx = EDIT_CTX;
  editingIdx = idx;
  const post = allPosts[idx];
  document.getElementById("edit-body").value = post.body || "";
  _updateHighlight();
  document.getElementById("edit-tags").value = (post.tags || []).join(" ");
  document.getElementById("edit-visibility").value = post.visibility || "contacts";
  document.getElementById("edit-comment-access").value = post.comment_access || "contacts";
  document.getElementById("edit-status").innerHTML = "";
  document.getElementById("edit-submit").disabled = false;
  document.getElementById("edit-overlay").hidden = false;
  document.getElementById("edit-body").focus();
}
function closeEdit() { document.getElementById("edit-overlay").hidden = true; }

async function submitEdit() {
  const post = allPosts[editingIdx];
  const body = _expandMentions(document.getElementById("edit-body").value);
  const tags = document.getElementById("edit-tags").value.trim().split(/\s+/).filter(Boolean);
  const visibility = document.getElementById("edit-visibility").value;
  const comment_access = document.getElementById("edit-comment-access").value;
  document.getElementById("edit-submit").disabled = true;
  document.getElementById("edit-status").innerHTML = '<span style="color:#aaa">Saving…</span>';

  const r = await apiFetch("/api/posts/" + post.id, {
    method: "PATCH",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({body, tags, visibility, comment_access}),
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
function fmtDate(ts) { if (!ts) return ""; return new Date(ts * 1000).toLocaleString(undefined, {dateStyle:"short",timeStyle:"short"}); }
function fmtSize(b) { if (b < 1024) return b + " B"; if (b < 1048576) return (b/1024).toFixed(1) + " KB"; return (b/1048576).toFixed(1) + " MB"; }

// ── profile ────────────────────────────────────────────────────────────────
function openProfile() { loadProfileAvatar(); document.getElementById("profile-overlay").hidden = false; }
function closeProfile() { document.getElementById("profile-overlay").hidden = true; }

function downloadBackup() {
  window.location.href = "/api/backup" + clientTokenParam(false);
}
async function downloadPrivateKey() {
  const passphrase = document.getElementById("privkey-passphrase").value;
  const status = document.getElementById("privkey-status");
  if (!passphrase) { status.style.color = "#e06c6c"; status.textContent = "Enter your passphrase."; return; }
  status.style.color = "#888"; status.textContent = "Verifying…";
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
    body: JSON.stringify({current_passphrase: current, new_passphrase: newPass, confirm_new_passphrase: confirm}),
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
let _handleCheckTimer = null;
let _handleAvailable = false;
let restoreFile = null;

function acceptSetupToken() {
  const token = document.getElementById("setup-token-input").value.trim();
  const err = document.getElementById("setup-token-error");
  if (!token) { err.textContent = "Token required."; return; }
  _setupToken = token;
  document.getElementById("setup-token-step").hidden = true;
  document.getElementById("setup-wizard-step").hidden = false;
}

function showSetupTab(tab) {
  document.getElementById("setup-new-form").hidden = tab !== "new";
  document.getElementById("setup-restore-form").hidden = tab !== "restore";
  document.getElementById("tab-new").classList.toggle("active", tab === "new");
  document.getElementById("tab-restore").classList.toggle("active", tab === "restore");
}

function checkHandleAvailability() {
  const input = document.getElementById("setup-handle");
  input.value = input.value.toLowerCase();
  const handle = input.value.trim();
  const status = document.getElementById("setup-handle-status");
  _handleAvailable = false;
  clearTimeout(_handleCheckTimer);
  if (!handle) { status.textContent = ""; return; }
  if (!/^[a-z_][a-z0-9_]*$/.test(handle)) {
    status.style.color = "#e06c6c";
    status.textContent = "Handle must start with a letter or _, followed by letters, digits, or _.";
    return;
  }
  status.style.color = "#888";
  status.textContent = "Checking…";
  _handleCheckTimer = setTimeout(async () => {
    try {
      const r = await fetch("/setup/check-handle?handle=" + encodeURIComponent(handle));
      const d = await r.json();
      if (r.ok) {
        status.style.color = "#6dbf6d";
        status.textContent = `✓ '${handle}' is available`;
        _handleAvailable = true;
      } else {
        status.style.color = "#e06c6c";
        status.textContent = d.detail || "Handle unavailable";
        _handleAvailable = false;
      }
    } catch { status.style.color = "#888"; status.textContent = "Could not check availability"; }
  }, 400);
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
  const email = document.getElementById("setup-owner-email").value.trim();
  const handle = document.getElementById("setup-handle").value.trim().toLowerCase();
  const pass = document.getElementById("setup-passphrase").value;
  const confirm = document.getElementById("setup-passphrase-confirm").value;
  const err = document.getElementById("setup-new-error");
  err.textContent = "";
  if (!email || !handle || !pass) { err.textContent = "All fields required."; return; }
  if (!_handleAvailable) { err.textContent = "Please choose an available handle."; return; }
  if (pass !== confirm) { err.textContent = "Passphrases do not match."; return; }
  try {
    const r = await fetch("/setup/new", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({passphrase: pass, confirm_passphrase: confirm, owner_identity: "google:" + email, setup_token: _setupToken, handle}),
    });
    const d = await r.json();
    if (r.status === 403) { _badSetupToken(d.detail); return; }
    if (!r.ok) { err.textContent = d.detail || "Error."; return; }
    location.reload();
  } catch { err.textContent = "Network error."; }
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

// ── dev menu ───────────────────────────────────────────────────────────────
function _toggleDevMenu() {
  const popup = document.getElementById('dev-menu-popup');
  popup.hidden = !popup.hidden;
  if (!popup.hidden) {
    const dismiss = e => {
      if (!popup.contains(e.target)) {
        popup.hidden = true;
        document.removeEventListener('click', dismiss, true);
      }
    };
    setTimeout(() => document.addEventListener('click', dismiss, true), 0);
  }
}

let _dbCheckIssues = [];

async function runDbCheck() {
  const overlay = document.getElementById('db-check-overlay');
  const body = document.getElementById('db-check-body');
  const fixBtn = document.getElementById('db-fix-btn');
  body.innerHTML = '<em style="color:#888">Running checks…</em>';
  fixBtn.hidden = true;
  overlay.hidden = false;
  try {
    const r = await apiFetch('/api/dev/db-check');
    const d = await r.json();
    _dbCheckIssues = d.issues || [];
    _renderDbCheckResults(_dbCheckIssues);
  } catch(e) {
    body.innerHTML = `<span style="color:#e06c6c">Error: ${esc(String(e))}</span>`;
  }
}

function _renderDbCheckResults(issues) {
  const body = document.getElementById('db-check-body');
  const fixBtn = document.getElementById('db-fix-btn');
  if (!issues.length) {
    body.innerHTML = '<span style="color:#4caf50">✓ No issues found.</span>';
    fixBtn.hidden = true;
    return;
  }
  const fixable = issues.filter(i => i.fix);
  fixBtn.hidden = fixable.length === 0;
  body.innerHTML = issues.map(issue => `
    <div style="margin-bottom:1rem;padding:0.6rem 0.75rem;background:#1a1a1a;border:1px solid #333;border-radius:6px">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.4rem">
        ${issue.fix ? `<input type="checkbox" class="db-fix-check" data-id="${esc(issue.id)}" checked style="accent-color:#4285f4">` : '<span style="color:#888;font-size:0.8rem">ℹ</span>'}
        <strong style="color:${issue.fix ? '#e0a060' : '#aaa'}">${esc(issue.title)}</strong>
        <span style="color:#555;font-size:0.8rem">(${issue.items.length})</span>
        ${issue.fix ? '' : '<span style="color:#555;font-size:0.75rem;margin-left:auto">manual fix required</span>'}
      </div>
      <ul style="margin:0 0 0 1.2rem;padding:0;color:#888;font-size:0.8rem;font-family:monospace">
        ${issue.items.slice(0, 10).map(i => `<li>${esc(i)}</li>`).join('')}
        ${issue.items.length > 10 ? `<li style="color:#555">…and ${issue.items.length - 10} more</li>` : ''}
      </ul>
    </div>
  `).join('');
}

async function runDbFix() {
  const checked = [...document.querySelectorAll('.db-fix-check:checked')].map(el => el.dataset.id);
  if (!checked.length) return;
  const fixBtn = document.getElementById('db-fix-btn');
  fixBtn.disabled = true;
  fixBtn.textContent = 'Fixing…';
  try {
    const r = await apiFetch('/api/dev/db-fix', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({fix_ids: checked}),
    });
    const d = await r.json();
    _dbCheckIssues = d.issues || [];
    _renderDbCheckResults(_dbCheckIssues);
  } catch(e) {
    document.getElementById('db-check-body').innerHTML = `<span style="color:#e06c6c">Fix error: ${esc(String(e))}</span>`;
  } finally {
    fixBtn.disabled = false;
    fixBtn.textContent = 'Fix selected';
  }
}
