use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use warp::Filter;

use crate::{identity::PersistentIdentity, network, vault};

struct UiState {
    id: PersistentIdentity,
    vault_path: PathBuf,
    rpc: String,
    client: reqwest::Client,
}

pub async fn serve(id: PersistentIdentity, vault_path: PathBuf, rpc: String, port: u16) -> Result<()> {
    let state = Arc::new(UiState {
        id,
        vault_path,
        rpc,
        client: reqwest::Client::new(),
    });

    let html = warp::path::end()
        .and(warp::get())
        .map(|| warp::reply::html(HTML));

    let get_secrets = warp::path!("api" / "secrets")
        .and(warp::get())
        .and(with_state(state.clone()))
        .and_then(handle_get_secrets);

    let post_sync = warp::path!("api" / "sync")
        .and(warp::post())
        .and(with_state(state.clone()))
        .and_then(handle_sync);

    let post_add = warp::path!("api" / "add")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_state(state.clone()))
        .and_then(handle_add);

    let cors = warp::cors()
        .allow_origin(&*format!("http://127.0.0.1:{}", port))
        .allow_methods(vec!["GET", "POST"])
        .allow_headers(vec!["content-type"]);

    let routes = html
        .or(get_secrets)
        .or(post_sync)
        .or(post_add)
        .with(cors);

    // Open browser
    let url = format!("http://127.0.0.1:{}", port);
    println!("🌐 Enigma UI: {}", url);
    #[cfg(target_os = "windows")]
    { let _ = std::process::Command::new("cmd").args(["/C", "start", &url]).spawn(); }
    #[cfg(target_os = "macos")]
    { let _ = std::process::Command::new("open").arg(&url).spawn(); }
    #[cfg(target_os = "linux")]
    { let _ = std::process::Command::new("xdg-open").arg(&url).spawn(); }

    warp::serve(routes).run(([127, 0, 0, 1], port)).await;
    Ok(())
}

fn with_state(
    state: Arc<UiState>,
) -> impl Filter<Extract = (Arc<UiState>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}

async fn handle_get_secrets(state: Arc<UiState>) -> Result<impl warp::Reply, warp::Rejection> {
    let vault_data = vault::load(&state.vault_path, &state.id.signing.secret)
        .unwrap_or_else(|_| vault::VaultData { version: 1, records: vec![], last_sync: None });

    Ok(warp::reply::json(&serde_json::json!({
        "secrets": vault_data.records,
        "last_sync": vault_data.last_sync,
        "did": state.id.did,
    })))
}

async fn handle_sync(state: Arc<UiState>) -> Result<impl warp::Reply, warp::Rejection> {
    // Announce key first
    let _ = state.client
        .post(format!("{}/announce_key", state.rpc))
        .send()
        .await;

    match network::sync_from_network(&state.client, &state.rpc, &state.id, &state.vault_path).await {
        Ok(count) => Ok(warp::reply::json(&serde_json::json!({ "synced": count }))),
        Err(e) => Ok(warp::reply::json(&serde_json::json!({ "error": e.to_string() }))),
    }
}

async fn handle_add(
    body: serde_json::Value,
    state: Arc<UiState>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let title = body["title"].as_str().unwrap_or_default();
    let url = body["url"].as_str().unwrap_or_default();
    let username = body["username"].as_str().unwrap_or_default();
    let password = body["password"].as_str().unwrap_or_default();
    let notes = body["notes"].as_str().unwrap_or_default();

    if title.is_empty() || password.is_empty() {
        return Ok(warp::reply::json(&serde_json::json!({ "error": "Title and password are required" })));
    }

    let record = enigma_core::models::SecretRecord::new(
        title.to_string(), username, password, notes, url,
    );

    // Encrypt and publish to mesh
    let inner = match enigma_core::EnigmaPayload::encrypt(&record, &state.id.encryption.public) {
        Ok(p) => p,
        Err(e) => return Ok(warp::reply::json(&serde_json::json!({ "error": e.to_string() }))),
    };
    let inner_bytes = match bincode::serialize(&inner) {
        Ok(b) => b,
        Err(e) => return Ok(warp::reply::json(&serde_json::json!({ "error": e.to_string() }))),
    };

    let publish_body = serde_json::json!({
        "recipient": state.id.did,
        "data": hex::encode(inner_bytes),
    });

    match state.client.post(format!("{}/publish", state.rpc)).json(&publish_body).send().await {
        Ok(res) => {
            let resp: serde_json::Value = res.json().await.unwrap_or_default();
            if resp.get("error").is_some() {
                return Ok(warp::reply::json(&resp));
            }
        }
        Err(e) => return Ok(warp::reply::json(&serde_json::json!({ "error": e.to_string() }))),
    }

    // Cache locally
    if let Ok(mut vd) = vault::load(&state.vault_path, &state.id.signing.secret) {
        vault::upsert(&mut vd, record);
        let _ = vault::save(&state.vault_path, &state.id.signing.secret, &vd);
    }

    Ok(warp::reply::json(&serde_json::json!({ "status": "ok" })))
}

const HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Enigma — Quantum-Safe Vault</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body { font-family: 'Inter', system-ui, -apple-system, sans-serif; }
  .secret-item { transition: background 0.15s; }
  .secret-item:hover { background: rgba(99,102,241,0.1); }
  .secret-item.active { background: rgba(99,102,241,0.2); border-left: 3px solid #6366f1; }
  .pass-field { font-family: monospace; letter-spacing: 0.1em; }
  .toast { animation: fadeOut 2s ease-in-out forwards; }
  @keyframes fadeOut { 0%{opacity:1} 70%{opacity:1} 100%{opacity:0} }
  .modal-enter { animation: slideUp 0.2s ease-out; }
  @keyframes slideUp { from{transform:translateY(20px);opacity:0} to{transform:translateY(0);opacity:1} }
</style>
</head>
<body class="bg-gray-950 text-gray-100 h-screen flex flex-col overflow-hidden">

<!-- Header -->
<header class="bg-gray-900 border-b border-gray-800 px-6 py-3 flex items-center justify-between shrink-0">
  <div class="flex items-center gap-3">
    <span class="text-2xl">🔐</span>
    <h1 class="text-xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">Enigma</h1>
    <span class="text-xs text-gray-600 hidden sm:inline">Quantum-Safe Vault</span>
  </div>
  <div class="flex items-center gap-3">
    <span id="didBadge" class="text-xs text-gray-600 hidden md:inline"></span>
    <button onclick="doSync()" id="syncBtn" class="bg-gray-800 hover:bg-gray-700 border border-gray-700 px-4 py-1.5 rounded-lg text-sm flex items-center gap-2">
      <span id="syncIcon">↻</span> Sync
    </button>
    <button onclick="openAddModal()" class="bg-indigo-600 hover:bg-indigo-500 px-4 py-1.5 rounded-lg text-sm font-medium">+ Add Secret</button>
  </div>
</header>

<!-- Main -->
<div class="flex flex-1 overflow-hidden">

  <!-- Sidebar -->
  <aside class="w-80 bg-gray-900 border-r border-gray-800 flex flex-col shrink-0">
    <div class="p-3">
      <input id="search" type="text" placeholder="Search vault..." oninput="filterList()"
             class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 placeholder-gray-500">
    </div>
    <div id="list" class="flex-1 overflow-y-auto"></div>
    <div id="statusBar" class="p-3 border-t border-gray-800 text-xs text-gray-600"></div>
  </aside>

  <!-- Detail -->
  <main id="detail" class="flex-1 overflow-y-auto p-8">
    <div id="emptyState" class="flex flex-col items-center justify-center h-full text-gray-600">
      <div class="text-6xl mb-4">🔐</div>
      <p class="text-lg mb-2">Welcome to Enigma</p>
      <p class="text-sm">Select a secret or click <strong>Sync</strong> to pull from the mesh</p>
    </div>
    <div id="detailContent" class="hidden max-w-xl"></div>
  </main>
</div>

<!-- Add Modal -->
<div id="addModal" class="hidden fixed inset-0 bg-black/60 flex items-center justify-center z-50" onclick="if(event.target===this)closeAddModal()">
  <div class="bg-gray-900 border border-gray-700 rounded-2xl p-6 w-full max-w-md modal-enter">
    <h2 class="text-lg font-bold mb-4">Add Secret</h2>
    <div class="space-y-3">
      <input id="fTitle" type="text" placeholder="Title (e.g. GitHub)" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500">
      <input id="fUrl" type="text" placeholder="URL (optional)" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500">
      <input id="fUser" type="text" placeholder="Username / Email" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500">
      <input id="fPass" type="password" placeholder="Password" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500">
      <textarea id="fNotes" placeholder="Notes (optional)" rows="2" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500 resize-none"></textarea>
    </div>
    <div class="flex justify-end gap-2 mt-5">
      <button onclick="closeAddModal()" class="px-4 py-2 text-sm text-gray-400 hover:text-white">Cancel</button>
      <button onclick="submitAdd()" id="addSubmit" class="bg-indigo-600 hover:bg-indigo-500 px-5 py-2 rounded-lg text-sm font-medium">Save to Mesh</button>
    </div>
  </div>
</div>

<!-- Toast -->
<div id="toast" class="hidden fixed bottom-6 right-6 bg-green-600 text-white px-4 py-2 rounded-lg text-sm shadow-lg toast"></div>

<script>
let secrets = [];
let selectedIdx = -1;

async function load() {
  try {
    const r = await fetch('/api/secrets');
    const d = await r.json();
    secrets = d.secrets || [];
    document.getElementById('didBadge').textContent = (d.did||'').slice(0,22)+'…';
    const sync = d.last_sync;
    if (sync) {
      const ago = Math.floor(Date.now()/1000) - sync;
      const h = ago<60?ago+'s':ago<3600?Math.floor(ago/60)+'m':Math.floor(ago/3600)+'h';
      document.getElementById('statusBar').textContent = secrets.length+' secrets · synced '+h+' ago';
    } else {
      document.getElementById('statusBar').textContent = secrets.length+' secrets · not synced yet';
    }
    renderList();
  } catch(e) { console.error(e); }
}

function renderList() {
  const q = document.getElementById('search').value.toLowerCase();
  const el = document.getElementById('list');
  const filtered = secrets.map((s,i)=>({...s,_i:i})).filter(s =>
    s.title.toLowerCase().includes(q) || (s.url||'').toLowerCase().includes(q) || s.username.toLowerCase().includes(q)
  );
  if (!filtered.length) {
    el.innerHTML = '<div class="p-4 text-center text-gray-600 text-sm">No matches</div>';
    return;
  }
  el.innerHTML = filtered.map(s => `
    <div class="secret-item px-4 py-3 cursor-pointer border-l-3 border-transparent ${s._i===selectedIdx?'active':''}" onclick="selectSecret(${s._i})">
      <div class="font-medium text-sm truncate">${esc(s.title)}</div>
      <div class="text-xs text-gray-500 truncate">${esc(s.username)}${s.url?' · '+esc(s.url):''}</div>
    </div>
  `).join('');
}

function filterList() { renderList(); }

function selectSecret(i) {
  selectedIdx = i;
  const s = secrets[i];
  document.getElementById('emptyState').classList.add('hidden');
  const dc = document.getElementById('detailContent');
  dc.classList.remove('hidden');
  const ts = new Date(s.created_at*1000).toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'});
  dc.innerHTML = `
    <h2 class="text-2xl font-bold mb-1">${esc(s.title)}</h2>
    ${s.url?`<a href="${esc(s.url)}" target="_blank" class="text-indigo-400 hover:text-indigo-300 text-sm">${esc(s.url)}</a>`:''}
    <div class="mt-6 space-y-4">
      <div>
        <label class="text-xs text-gray-500 uppercase tracking-wider">Username</label>
        <div class="flex items-center gap-2 mt-1">
          <span class="text-sm flex-1 font-mono bg-gray-900 border border-gray-800 rounded px-3 py-2">${esc(s.username)}</span>
          <button onclick="copyText('${esc(s.username)}')" class="text-xs bg-gray-800 hover:bg-gray-700 border border-gray-700 px-3 py-2 rounded">Copy</button>
        </div>
      </div>
      <div>
        <label class="text-xs text-gray-500 uppercase tracking-wider">Password</label>
        <div class="flex items-center gap-2 mt-1">
          <span id="passDisplay" class="pass-field text-sm flex-1 bg-gray-900 border border-gray-800 rounded px-3 py-2">••••••••</span>
          <button onclick="togglePass(${i})" id="toggleBtn" class="text-xs bg-gray-800 hover:bg-gray-700 border border-gray-700 px-3 py-2 rounded">Show</button>
          <button onclick="copyText(secrets[${i}].password)" class="text-xs bg-indigo-600 hover:bg-indigo-500 px-3 py-2 rounded font-medium">Copy</button>
        </div>
      </div>
      ${s.notes?`<div><label class="text-xs text-gray-500 uppercase tracking-wider">Notes</label><p class="text-sm text-gray-300 mt-1 whitespace-pre-wrap">${esc(s.notes)}</p></div>`:''}
      <div class="text-xs text-gray-600 pt-2">Created ${ts}</div>
    </div>
  `;
  renderList();
}

let passVisible = false;
function togglePass(i) {
  passVisible = !passVisible;
  document.getElementById('passDisplay').textContent = passVisible ? secrets[i].password : '••••••••';
  document.getElementById('toggleBtn').textContent = passVisible ? 'Hide' : 'Show';
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard'));
}

async function doSync() {
  const btn = document.getElementById('syncBtn');
  const icon = document.getElementById('syncIcon');
  btn.disabled = true;
  icon.style.animation = 'spin 1s linear infinite';
  icon.style.display = 'inline-block';
  const style = document.createElement('style');
  style.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
  document.head.appendChild(style);
  try {
    const r = await fetch('/api/sync', {method:'POST'});
    const d = await r.json();
    if (d.error) { showToast('Sync failed: '+d.error, true); }
    else { showToast('Synced '+d.synced+' secrets'); await load(); }
  } catch(e) { showToast('Sync failed', true); }
  btn.disabled = false;
  icon.style.animation = '';
  style.remove();
}

function openAddModal() { document.getElementById('addModal').classList.remove('hidden'); document.getElementById('fTitle').focus(); }
function closeAddModal() { document.getElementById('addModal').classList.add('hidden'); ['fTitle','fUrl','fUser','fPass','fNotes'].forEach(id=>document.getElementById(id).value=''); }

async function submitAdd() {
  const body = {
    title: document.getElementById('fTitle').value,
    url: document.getElementById('fUrl').value,
    username: document.getElementById('fUser').value,
    password: document.getElementById('fPass').value,
    notes: document.getElementById('fNotes').value,
  };
  if (!body.title || !body.password) { showToast('Title and password required', true); return; }
  const btn = document.getElementById('addSubmit');
  btn.disabled = true; btn.textContent = 'Encrypting...';
  try {
    const r = await fetch('/api/add', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
    const d = await r.json();
    if (d.error) { showToast(d.error, true); }
    else { showToast('Secret stored on the mesh'); closeAddModal(); await load(); }
  } catch(e) { showToast('Failed to add', true); }
  btn.disabled = false; btn.textContent = 'Save to Mesh';
}

function showToast(msg, err) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'fixed bottom-6 right-6 px-4 py-2 rounded-lg text-sm shadow-lg toast ' + (err?'bg-red-600':'bg-green-600') + ' text-white';
  setTimeout(()=>t.className='hidden', 2500);
}

function esc(s) { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; }

load();
</script>
</body>
</html>"##;
