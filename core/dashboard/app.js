const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
let key = sessionStorage.getItem('forenzx_admin_key') || '';
let state = {servers:[], packs:[], jobs:[], summary:{}, events:[]};

function headers(json=true){const h={'X-API-Key':key}; if(json) h['Content-Type']='application/json'; return h}
async function api(path, opts={}){
  const res=await fetch(path,{...opts,headers:{...headers(opts.body!==undefined),...(opts.headers||{})}});
  const ct=res.headers.get('content-type')||'';
  const body=ct.includes('json')?await res.json():await res.text();
  if(!res.ok) throw new Error(body?.detail||body?.error||body||`HTTP ${res.status}`);
  return body;
}
function esc(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
function ago(v){if(!v)return '—';const d=new Date(v), s=Math.max(0,(Date.now()-d)/1000); if(s<60)return `${Math.floor(s)}s ago`; if(s<3600)return `${Math.floor(s/60)}m ago`; if(s<86400)return `${Math.floor(s/3600)}h ago`; return d.toLocaleString()}
function badge(s){return `<span class="badge ${esc(s)}">${esc(s)}</span>`}
function flash(msg,error=false){const el=$('#flash');el.textContent=msg;el.classList.remove('hidden','error');if(error)el.classList.add('error');setTimeout(()=>el.classList.add('hidden'),4500)}
function openModal(id){$('#'+id).classList.add('open')} function closeModal(id){$('#'+id).classList.remove('open')}

const pageMeta={overview:['Overview','Control plane, forensic engine and remote MCP registry.'],servers:['MCP Servers','Register, probe and maintain remote MCP endpoints.'],packs:['Forensic Packs','Container-pinned deterministic forensic capabilities.'],jobs:['Jobs','Persistent analysis execution history.'],maintenance:['Maintenance','Small, safe operations for a low-maintenance deployment.'],audit:['Audit','Management and health-check activity.']};
function showView(name){$$('.view').forEach(v=>v.classList.toggle('active',v.id===`view-${name}`));$$('#nav button').forEach(b=>b.classList.toggle('active',b.dataset.view===name));$('#pageTitle').textContent=pageMeta[name][0];$('#pageSub').textContent=pageMeta[name][1];}
$$('#nav button').forEach(b=>b.onclick=()=>showView(b.dataset.view));
$$('[data-close]').forEach(b=>b.onclick=()=>closeModal(b.dataset.close));

async function unlock(){key=$('#adminKey').value.trim(); if(!key)return; sessionStorage.setItem('forenzx_admin_key',key); try{await refreshAll(); closeModal('keyModal'); $('#apiDot').classList.add('ok');$('#apiStatus').textContent='Admin connected'}catch(e){sessionStorage.removeItem('forenzx_admin_key'); key=''; flash(e.message,true)}}
$('#unlock').onclick=unlock; $('#adminKey').addEventListener('keydown',e=>{if(e.key==='Enter')unlock()});
$('#changeKey').onclick=()=>{sessionStorage.removeItem('forenzx_admin_key');key='';$('#adminKey').value='';openModal('keyModal')};

async function refreshAll(){
  const [summary,servers,packs,jobs,events]=await Promise.all([
    api('/api/v1/ops/summary'),api('/api/v1/mcp-servers'),api('/api/v1/ops/packs'),api('/api/v1/ops/jobs?limit=100'),api('/api/v1/ops/events?limit=150')
  ]);
  state={summary,servers:servers.servers,packs:packs.packs,jobs:jobs.jobs,events:events.events}; renderAll();
}
$('#refreshAll').onclick=()=>refreshAll().then(()=>flash('Dashboard refreshed')).catch(e=>flash(e.message,true));

function renderAll(){renderOverview();renderServers();renderPacks();renderJobs();renderMaintenance();renderAudit()}
function renderOverview(){const s=state.summary; const down=state.servers.filter(x=>x.enabled&&x.last_status!=='READY').length;
  $('#overviewCards').innerHTML=[['MCP servers',s.mcp_servers||0,`${s.mcp_ready||0} ready`],['Attention',down,down?'server checks need attention':'all registered endpoints healthy'],['Jobs',s.jobs||0,`${s.failed_jobs||0} failed`],['Forensic packs',s.packs||0,`${Object.keys(s.pack_errors||{}).length} registry issue(s)`]].map(x=>`<div class="metric"><div class="label">${x[0]}</div><div class="value">${x[1]}</div><div class="meta">${x[2]}</div></div>`).join('');
  $('#overviewServers').innerHTML=state.servers.length?`<div class="mini-list">${state.servers.slice(0,7).map(x=>`<div class="mini-row"><div><strong>${esc(x.name)}</strong><span class="sub">${esc(x.server_type)} · ${x.last_latency_ms??'—'} ms</span></div>${badge(x.enabled?x.last_status:'DISABLED')}</div>`).join('')}</div>`:'<div class="empty">No remote MCP servers yet.</div>';
  $('#overviewPacks').innerHTML=state.packs.length?`<div class="mini-list">${state.packs.map(x=>`<div class="mini-row"><div><strong>${esc(x.name)}</strong><span class="sub">v${esc(x.version)} · ${esc(x.id)}</span></div>${badge(x.registry_error?'DEGRADED':x.enabled?'READY':'DISABLED')}</div>`).join('')}</div>`:'<div class="empty">No packs loaded.</div>';
  $('#overviewJobs').innerHTML=jobsTable(state.jobs.slice(0,8));
}

function renderServers(){const q=($('#serverSearch').value||'').toLowerCase(), f=$('#serverFilter').value; let rows=state.servers.filter(x=>{const hay=[x.name,x.url,x.server_type,...x.tags].join(' ').toLowerCase();const st=x.enabled?x.last_status:'DISABLED';return (!q||hay.includes(q))&&(f==='all'||st===f)});
  $('#serverRows').innerHTML=rows.length?rows.map(x=>`<tr><td>${badge(x.enabled?x.last_status:'DISABLED')}<span class="sub">${ago(x.last_checked_at)}</span></td><td><span class="server-name">${esc(x.name)}</span><span class="sub">${esc(x.tags.join(', '))}</span></td><td><span class="type-tag">${esc(x.server_type)}</span></td><td><div class="endpoint" title="${esc(x.url)}">${esc(x.url)}</div><span class="sub">${esc(x.transport)}</span></td><td>${x.last_latency_ms==null?'—':`${x.last_latency_ms} ms`}</td><td>${x.last_tools.length}</td><td><div class="actions"><button class="btn small ghost" data-act="probe" data-id="${x.id}">Probe</button><button class="btn small ghost" data-act="tools" data-id="${x.id}">Tools</button><button class="btn small ghost" data-act="toggle" data-id="${x.id}">${x.enabled?'Disable':'Enable'}</button>${x.maintenance_url?`<button class="btn small ghost" data-act="restart" data-id="${x.id}">Restart</button>`:''}<button class="btn small ghost" data-act="edit" data-id="${x.id}">Edit</button><button class="btn small danger" data-act="delete" data-id="${x.id}">Delete</button></div></td></tr>`).join(''):`<tr><td colspan="7"><div class="empty">No matching servers.</div></td></tr>`;
}
$('#serverSearch').oninput=renderServers;$('#serverFilter').onchange=renderServers;
$('#serverRows').onclick=async e=>{const b=e.target.closest('button[data-act]');if(!b)return;const id=b.dataset.id, act=b.dataset.act, srv=state.servers.find(x=>x.id===id);try{
  if(act==='probe'){b.disabled=true;const r=await api(`/api/v1/mcp-servers/${id}/probe`,{method:'POST'});flash(`${srv.name}: ${r.status}${r.latency_ms!=null?` · ${r.latency_ms} ms`:''}`);await refreshAll()}
  if(act==='tools'){const r=await api(`/api/v1/mcp-servers/${id}/tools`);$('#toolsTitle').textContent=`${srv.name} · ${r.tools.length} tools`;$('#toolsContent').textContent=JSON.stringify(r.tools,null,2);openModal('toolsModal')}
  if(act==='toggle'){await api(`/api/v1/mcp-servers/${id}/toggle`,{method:'POST',body:JSON.stringify({enabled:!srv.enabled})});await refreshAll()}
  if(act==='restart'){if(confirm(`Send restart request to ${srv.name}?`)){await api(`/api/v1/mcp-servers/${id}/restart`,{method:'POST'});flash('Restart request accepted');setTimeout(()=>refreshAll(),1200)}}
  if(act==='edit')openServerModal(srv);
  if(act==='delete'){if(confirm(`Delete ${srv.name} from the registry? This does not delete the remote server.`)){await api(`/api/v1/mcp-servers/${id}`,{method:'DELETE'});await refreshAll();flash('Server removed from registry')}}
}catch(err){flash(err.message,true)}finally{b.disabled=false}};

function openServerModal(srv=null){$('#serverForm').reset();$('#serverModalTitle').textContent=srv?'Edit MCP server':'Add MCP server';$('#serverId').value=srv?.id||'';$('#serverName').value=srv?.name||'';$('#serverType').value=srv?.server_type||'generic';$('#serverUrl').value=srv?.url||'';$('#serverTransport').value=srv?.transport||'streamable_http';$('#serverAuthType').value=srv?.auth_type||'none';$('#serverMaintenance').value=srv?.maintenance_url||'';$('#serverTags').value=(srv?.tags||[]).join(', ');$('#serverNotes').value=srv?.notes||'';$('#serverEnabled').checked=srv?.enabled??true;openModal('serverModal')}
$('#addServerTop').onclick=()=>openServerModal();$('#addServerInline').onclick=()=>openServerModal();
$('#serverForm').onsubmit=async e=>{e.preventDefault();const id=$('#serverId').value;const payload={name:$('#serverName').value.trim(),server_type:$('#serverType').value,url:$('#serverUrl').value.trim(),transport:$('#serverTransport').value,enabled:$('#serverEnabled').checked,auth_type:$('#serverAuthType').value,tags:$('#serverTags').value.split(',').map(x=>x.trim()).filter(Boolean),notes:$('#serverNotes').value.trim()};const secret=$('#serverSecret').value;if(secret)payload.auth_secret=secret;const maint=$('#serverMaintenance').value.trim();if(maint)payload.maintenance_url=maint;else if(id)payload.clear_maintenance_url=true;try{await api(id?`/api/v1/mcp-servers/${id}`:'/api/v1/mcp-servers',{method:id?'PUT':'POST',body:JSON.stringify(payload)});closeModal('serverModal');await refreshAll();flash(id?'Server updated':'Server added')}catch(err){flash(err.message,true)}};

function renderPacks(){$('#packList').innerHTML=state.packs.length?state.packs.map(p=>`<div class="pack-row"><div><h3>${esc(p.name)} <span class="type-tag">${esc(p.id)}</span></h3><p>${esc(p.description)}</p></div><div><span class="sub">Platforms</span>${esc(p.supported_platforms.join(', '))}<span class="sub">Inputs: ${esc(p.supported_inputs.join(', '))}</span></div><div><span class="sub">Container digest</span><div class="digest">${esc(p.pinned_image_digest)}</div></div><div>${badge(p.registry_error?'DEGRADED':p.enabled?'READY':'DISABLED')}<div class="actions" style="margin-top:8px">${p.registry_error?`<button class="btn small primary" data-pack-digest="${esc(p.id)}">Set real digest</button>`:''}</div></div>${p.registry_error?`<div style="grid-column:1/-1;color:#eeb25c;font-size:11px">${esc(p.registry_error)}</div>`:''}</div>`).join(''):'<div class="empty">No forensic packs loaded.</div>'}
$('#reloadPacks').onclick=async()=>{try{await api('/api/v1/ops/packs/reload',{method:'POST'});await refreshAll();flash('Packs reloaded')}catch(e){flash(e.message,true)}};
$('#packList').onclick=async e=>{const b=e.target.closest('[data-pack-digest]');if(!b)return;const id=b.dataset.packDigest;const digest=prompt(`Paste the verified RepoDigest for ${id}:\nsha256:<64 hex>`);if(!digest)return;try{await api(`/api/v1/ops/packs/${encodeURIComponent(id)}/digest`,{method:'POST',body:JSON.stringify({digest})});await refreshAll();flash('Digest updated and pack reloaded')}catch(err){flash(err.message,true)}};

function jobsTable(rows){if(!rows.length)return '<div class="empty">No jobs yet.</div>';return `<div class="table-wrap"><table><thead><tr><th>State</th><th>Job</th><th>Case / Evidence</th><th>Pack</th><th>Progress</th><th>Updated</th></tr></thead><tbody>${jobTr(rows)}</tbody></table></div>`}
function jobTr(rows){return rows.map(j=>`<tr><td>${badge(j.state)}</td><td><span class="endpoint">${esc(j.job_id)}</span><span class="sub">${esc(j.current_stage)}</span></td><td>${esc(j.case_id)}<span class="sub">${esc(j.evidence_id)}</span></td><td>${esc(j.pack_id)}</td><td><div class="progress"><i style="width:${Number(j.progress_percent||0)}%"></i></div><span class="sub">${Number(j.progress_percent||0)}%</span></td><td>${ago(j.updated_at)}</td></tr>`).join('')}
function renderJobs(){$('#jobRows').innerHTML=state.jobs.length?jobTr(state.jobs):'<tr><td colspan="6"><div class="empty">No jobs yet.</div></td></tr>'}

function renderMaintenance(){const s=state.summary;$('#maintenanceCards').innerHTML=[['Database',`${((s.database_bytes||0)/1024).toFixed(1)} KB`,'SQLite + WAL'],['Registry',s.mcp_servers||0,'managed MCP endpoints'],['Jobs',s.jobs||0,'persistent records'],['Pack issues',Object.keys(s.pack_errors||{}).length,'blocked/degraded capabilities']].map(x=>`<div class="metric"><div class="label">${x[0]}</div><div class="value">${x[1]}</div><div class="meta">${x[2]}</div></div>`).join('')}
$('#backupDb').onclick=async()=>{try{const r=await api('/api/v1/ops/maintenance/backup',{method:'POST'});flash(`Backup created: ${r.file}`);const a=document.createElement('a');a.href=r.download;a.target='_blank';a.click();await refreshAll()}catch(e){flash(e.message,true)}};
$('#vacuumDb').onclick=async()=>{try{await api('/api/v1/ops/maintenance/vacuum',{method:'POST'});await refreshAll();flash('Database vacuum complete')}catch(e){flash(e.message,true)}};
$('#pruneAudit').onclick=async()=>{try{const days=Number($('#pruneDays').value||30);const r=await api('/api/v1/ops/maintenance/prune',{method:'POST',body:JSON.stringify({days})});await refreshAll();flash(`Pruned ${r.deleted} old audit events`)}catch(e){flash(e.message,true)}};
$('#exportRegistry').onclick=async()=>{try{const r=await api('/api/v1/ops/registry-export');const blob=new Blob([JSON.stringify(r,null,2)],{type:'application/json'}),u=URL.createObjectURL(blob),a=document.createElement('a');a.href=u;a.download=`forenzx-mcp-registry-${new Date().toISOString().slice(0,10)}.json`;a.click();URL.revokeObjectURL(u)}catch(e){flash(e.message,true)}};

function renderAudit(){$('#auditRows').innerHTML=state.events.length?state.events.map(e=>`<tr><td>${ago(e.ts)}<span class="sub">${esc(e.ts)}</span></td><td>${esc(e.actor)}</td><td>${esc(e.action)}</td><td>${esc(e.target_id||'—')}</td><td>${e.success?badge('READY'):badge('DOWN')}</td><td class="endpoint">${esc(e.details_json||'{}')}</td></tr>`).join(''):'<tr><td colspan="6"><div class="empty">No audit events.</div></td></tr>'}

if(key){$('#adminKey').value=key;refreshAll().then(()=>{closeModal('keyModal');$('#apiDot').classList.add('ok');$('#apiStatus').textContent='Admin connected'}).catch(()=>openModal('keyModal'))}else openModal('keyModal');
setInterval(()=>{if(key)refreshAll().catch(()=>{})},30000);
