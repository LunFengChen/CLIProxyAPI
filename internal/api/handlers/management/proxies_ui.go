package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// proxiesUIHTML is the self-contained proxy pool management page.
// It talks to the /v0/management/proxies API using the secret key from
// the URL query parameter ?key=<secret-key> or the Authorization header.
const proxiesUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proxy Pool — CLI Proxy API</title>
<style>
  :root{--bg:#0f111a;--surface:#1a1d2e;--border:#2d3153;--accent:#6c8eff;--text:#e0e4ff;--muted:#7b82a8;--red:#ff5c6e;--green:#5cffa0;--yellow:#ffd86c}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font:14px/1.6 'Segoe UI',system-ui,sans-serif;padding:16px}
  h1{font-size:18px;font-weight:600;margin-bottom:16px}
  .toolbar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
  input,select{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:6px;font-size:13px}
  input:focus,select:focus{outline:1px solid var(--accent)}
  button{padding:6px 14px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500}
  .btn-primary{background:var(--accent);color:#fff}
  .btn-danger{background:var(--red);color:#fff}
  .btn-sm{padding:3px 9px;font-size:12px}
  .group-header{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:8px 12px;margin:12px 0 4px;font-weight:600;color:var(--accent);cursor:pointer;display:flex;justify-content:space-between;align-items:center}
  table{width:100%;border-collapse:collapse;margin-bottom:8px}
  th,td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--border);font-size:13px}
  th{color:var(--muted);font-weight:500}
  tr:hover td{background:rgba(108,142,255,.05)}
  .tag{display:inline-block;padding:1px 7px;border-radius:99px;font-size:11px;background:var(--surface);border:1px solid var(--border)}
  .tag-green{border-color:var(--green);color:var(--green)}
  .tag-red{border-color:var(--red);color:var(--red)}
  .tag-yellow{border-color:var(--yellow);color:var(--yellow)}
  .modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:100;align-items:center;justify-content:center}
  .modal-bg.open{display:flex}
  .modal{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;width:420px;max-width:95vw}
  .modal h2{font-size:15px;margin-bottom:14px}
  .form-row{display:flex;flex-direction:column;gap:4px;margin-bottom:12px}
  .form-row label{font-size:12px;color:var(--muted)}
  .form-row input{width:100%}
  .modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
  .error{color:var(--red);font-size:12px;margin-top:8px}
  #auth-list{max-height:240px;overflow-y:auto;margin:8px 0}
  .auth-item{display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);font-size:13px}
  .auth-item input{width:16px;height:16px}
  .url-cell{max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
</style>
</head>
<body>
<h1>🔌 Proxy Pool</h1>
<div class="toolbar">
  <button class="btn-primary" onclick="openAdd()">+ Add Proxy</button>
  <input id="filter-group" placeholder="Filter group…" oninput="render()" style="width:160px">
  <span id="status" style="color:var(--muted);font-size:12px"></span>
</div>
<div id="root"></div>

<!-- Add/Edit modal -->
<div class="modal-bg" id="modal-edit">
  <div class="modal">
    <h2 id="modal-title">Add Proxy</h2>
    <div class="form-row"><label>URL (socks5://user:pass@host:port or http://…)</label><input id="f-url" placeholder="socks5://..."></div>
    <div class="form-row"><label>Group <small style="color:var(--muted)">(free text, e.g. US-California)</small></label>
      <input id="f-group" list="group-list" placeholder="US-California">
      <datalist id="group-list"></datalist>
    </div>
    <div class="form-row"><label>Label (optional)</label><input id="f-label" placeholder="spare note"></div>
    <div class="form-row" id="f-disabled-row" style="display:none">
      <label><input type="checkbox" id="f-disabled"> Disabled</label>
    </div>
    <p class="error" id="modal-err"></p>
    <div class="modal-actions">
      <button onclick="closeModals()">Cancel</button>
      <button class="btn-primary" onclick="submitEdit()">Save</button>
    </div>
  </div>
</div>

<!-- Assign modal -->
<div class="modal-bg" id="modal-assign">
  <div class="modal">
    <h2>Assign proxy to auth accounts</h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:8px">Select accounts to bind this proxy URL. Previously assigned accounts are pre-checked.</p>
    <input id="auth-filter" placeholder="Filter accounts…" oninput="filterAuths()" style="width:100%;margin-bottom:6px">
    <div id="auth-list"></div>
    <p class="error" id="assign-err"></p>
    <div class="modal-actions">
      <button onclick="closeModals()">Cancel</button>
      <button class="btn-primary" onclick="submitAssign()">Assign</button>
    </div>
  </div>
</div>

<script>
const API = '/v0/management';
let proxies = [], allAuths = [];
let editingID = null, assigningID = null;

// Retrieve key: ?key=xxx query param OR localStorage
function getKey() {
  const p = new URLSearchParams(location.search).get('key');
  if (p) { localStorage.setItem('cpa_key', p); return p; }
  return localStorage.getItem('cpa_key') || '';
}
function headers() {
  const k = getKey();
  return k ? {'Content-Type':'application/json','Authorization':'Bearer '+k} : {'Content-Type':'application/json'};
}

async function load() {
  try {
    const r = await fetch(API+'/proxies', {headers:headers()});
    if (r.status === 404) { document.getElementById('status').textContent='Management API not available'; return; }
    if (!r.ok) {
      const t = await r.text();
      document.getElementById('status').textContent = 'Error: '+t;
      return;
    }
    proxies = await r.json();
    // Collect auth list for assign modal (best-effort)
    try {
      const ar = await fetch(API+'/auth-files', {headers:headers()});
      if (ar.ok) allAuths = (await ar.json()) || [];
    } catch(e){}
    render();
  } catch(e) { document.getElementById('status').textContent = 'Load failed: '+e.message; }
}

function render() {
  const filter = document.getElementById('filter-group').value.trim().toLowerCase();
  const byGroup = {};
  proxies.forEach(p => {
    const g = p.group || '(ungrouped)';
    if (filter && !g.toLowerCase().includes(filter)) return;
    (byGroup[g] = byGroup[g]||[]).push(p);
  });
  // Populate group datalist
  const dl = document.getElementById('group-list');
  dl.innerHTML = '';
  [...new Set(proxies.map(p=>p.group||''))].filter(Boolean).forEach(g=>{
    const o=document.createElement('option'); o.value=g; dl.appendChild(o);
  });

  const root = document.getElementById('root');
  if (!Object.keys(byGroup).length) { root.innerHTML='<p style="color:var(--muted);margin-top:16px">No proxies yet.</p>'; return; }
  root.innerHTML = Object.entries(byGroup).sort((a,b)=>a[0].localeCompare(b[0])).map(function([g,list]){
    return '<div class="group-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'\':\' none\'">'
      +'<span>'+esc(g)+' <span style="color:var(--muted);font-weight:400">('+list.length+')</span></span>'
      +'<span style="font-size:12px;color:var(--muted)">▾ click to collapse</span>'
      +'</div>'
      +'<table><thead><tr><th>URL</th><th>Label</th><th>Group</th><th>Status</th><th>Assigned to</th><th></th></tr></thead>'
      +'<tbody>'+list.map(function(p){
        return '<tr>'
          +'<td class="url-cell" title="'+esc(p.url)+'">'+esc(p.url)+'</td>'
          +'<td>'+esc(p.label||'')+'</td>'
          +'<td><span class="tag">'+esc(p.group||'')+'</span></td>'
          +'<td>'+(p.disabled?'<span class="tag tag-red">disabled</span>':(p.assigned_to&&p.assigned_to.length?'<span class="tag tag-green">in use</span>':'<span class="tag">idle</span>'))+'</td>'
          +'<td style="font-size:12px;color:var(--muted)">'+(p.assigned_to||[]).length+' account(s)</td>'
          +'<td style="white-space:nowrap;display:flex;gap:4px;padding:7px 6px">'
          +'<button class="btn-primary btn-sm" onclick="openAssign(\''+p.id+'\')">Assign</button>'
          +'<button class="btn-sm" style="background:var(--surface);color:var(--text);border:1px solid var(--border)" onclick="openEdit(\''+p.id+'\')">Edit</button>'
          +'<button class="btn-danger btn-sm" onclick="del(\''+p.id+'\')">Del</button>'
          +'</td></tr>';
      }).join('')
      +'</tbody></table>';
  }).join('');
  document.getElementById('status').textContent = proxies.length+' proxi'+(proxies.length===1?'y':'es');
}

function esc(s){ const d=document.createElement('div'); d.textContent=String(s||''); return d.innerHTML; }

function openAdd(){ editingID=null; document.getElementById('modal-title').textContent='Add Proxy'; document.getElementById('f-url').value=''; document.getElementById('f-group').value=''; document.getElementById('f-label').value=''; document.getElementById('f-disabled').checked=false; document.getElementById('f-disabled-row').style.display='none'; document.getElementById('modal-err').textContent=''; document.getElementById('modal-edit').classList.add('open'); document.getElementById('f-url').focus(); }
function openEdit(id){ const p=proxies.find(x=>x.id===id); if(!p)return; editingID=id; document.getElementById('modal-title').textContent='Edit Proxy'; document.getElementById('f-url').value=p.url||''; document.getElementById('f-group').value=p.group||''; document.getElementById('f-label').value=p.label||''; document.getElementById('f-disabled').checked=!!p.disabled; document.getElementById('f-disabled-row').style.display=''; document.getElementById('modal-err').textContent=''; document.getElementById('modal-edit').classList.add('open'); }

async function submitEdit(){
  const url=document.getElementById('f-url').value.trim();
  if(!url){ document.getElementById('modal-err').textContent='URL is required'; return; }
  const body={url, group:document.getElementById('f-group').value.trim(), label:document.getElementById('f-label').value.trim(), disabled:document.getElementById('f-disabled').checked};
  const method=editingID?'PUT':'POST';
  const endpoint=editingID?API+'/proxies/'+editingID:API+'/proxies';
  try{
    const r=await fetch(endpoint,{method,headers:headers(),body:JSON.stringify(body)});
    if(!r.ok){document.getElementById('modal-err').textContent=await r.text();return;}
    closeModals(); await load();
  }catch(e){document.getElementById('modal-err').textContent=e.message;}
}

async function del(id){
  if(!confirm('Delete this proxy?'))return;
  const r=await fetch(API+'/proxies/'+id,{method:'DELETE',headers:headers()});
  if(!r.ok){alert('Error: '+(await r.text()));return;}
  await load();
}

function openAssign(id){
  assigningID=id;
  const p=proxies.find(x=>x.id===id);
  const assigned=new Set((p&&p.assigned_to)||[]);
  document.getElementById('auth-list').innerHTML=allAuths.length?allAuths.map(function(a){
    return '<div class="auth-item">'
      +'<input type="checkbox" id="ck-'+esc(a.id)+'" value="'+esc(a.id)+'"'+(assigned.has(a.id)?' checked':')+'>'
      +'<label for="ck-'+esc(a.id)+'" style="cursor:pointer;flex:1">'
      +'<strong>'+esc(a.id)+'</strong>'
      +(a.provider?'<span style="color:var(--muted);font-size:11px"> '+esc(a.provider)+'</span>':'')
      +(a.label?'<span style="color:var(--muted);font-size:11px"> '+esc(a.label)+'</span>':'')
      +'</label></div>';
  }).join(''):'<p style="color:var(--muted)">No auth accounts found.</p>';
  document.getElementById('auth-filter').value='';
  document.getElementById('assign-err').textContent='';
  document.getElementById('modal-assign').classList.add('open');
}

function filterAuths(){
  const q=document.getElementById('auth-filter').value.trim().toLowerCase();
  document.querySelectorAll('#auth-list .auth-item').forEach(el=>{
    el.style.display=q&&!el.textContent.toLowerCase().includes(q)?'none':'flex';
  });
}

async function submitAssign(){
  const checked=[...document.querySelectorAll('#auth-list input:checked')].map(el=>el.value);
  if(!checked.length){document.getElementById('assign-err').textContent='Select at least one account';return;}
  try{
    const r=await fetch(API+'/proxies/'+assigningID+'/assign',{method:'POST',headers:headers(),body:JSON.stringify({auth_ids:checked})});
    if(!r.ok){document.getElementById('assign-err').textContent=await r.text();return;}
    closeModals(); await load();
  }catch(e){document.getElementById('assign-err').textContent=e.message;}
}

function closeModals(){ document.querySelectorAll('.modal-bg').forEach(m=>m.classList.remove('open')); }
document.querySelectorAll('.modal-bg').forEach(m=>m.addEventListener('click',e=>{if(e.target===m)closeModals();}));
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModals();});
load();
</script>
</body>
</html>`

// ServeProxiesUI serves the self-contained proxy pool management page.
// Access: GET /proxies-ui?key=<secret-key>
// Authentication: pass the management secret key as the ?key= query param (stored
// in localStorage on first use) or as Authorization: Bearer <key> header.
// This page is intentionally served outside the /v0/management/ middleware so
// the browser can load it without CORS issues; the API calls it makes do go
// through the normal management auth middleware.
func (h *Handler) ServeProxiesUI(c *gin.Context) {
	if h.cfg != nil && (h.cfg.Home.Enabled || h.cfg.RemoteManagement.DisableControlPanel) {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	// Quick sanity: ensure management routes are actually enabled (secret-key set).
	// We only block serving the HTML if there's genuinely no management config at all.
	if h == nil || h.cfg == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, strings.TrimSpace(proxiesUIHTML))
}
