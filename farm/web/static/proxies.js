'use strict';
let proxyPanel=null,proxyPanelLoading=null;
function proxyNote(id,text){$(id).textContent=text;}
function proxyMode(){
 const f=$('#catalog-bind-form'),chained=f.elements.mode.value==='catalog';
 $('#catalog-node-field').hidden=chained;f.elements.node_name.disabled=chained;
 $('#catalog-route-field').hidden=!chained;f.elements.proxy_id.disabled=!chained;
}
function proxySelect(el,rows,placeholder){
 const current=el.value;
 el.innerHTML=`<option value="">${esc(placeholder)}</option>`+rows.map(([value,label])=>`<option value="${esc(value)}">${esc(label)}</option>`).join('');
 if(rows.some(([v])=>v===current))el.value=current;
}
function renderProxyAccounts(){
 if(!proxyPanel)return;
 const query=$('#proxy-account-search').value.trim().toLowerCase();
 $('#proxy-accounts-body').innerHTML=proxyPanel.accounts.filter(a=>[a.id,a.label].some(v=>String(v).toLowerCase().includes(query))).map(a=>{
  const b=a.binding||{};
  return `<tr><td><label class="check"><input type="checkbox" data-proxy-account="${a.id}">#${a.id} ${esc(a.label)}</label></td><td>${a.paused?badge('paused'):'未暂停'}</td><td>${b.mode==='clash_pool'?'Clash 直出':b.mode==='catalog'?'海外代理':'原有出口'}<small>${esc(b.name||'尚未配置')}</small></td><td>${esc(b.front_node||'—')}</td><td><button class="secondary mini" data-bind-proxy-account="${a.id}">配置</button></td></tr>`;
 }).join('')||empty(5);
}
function loadProxyPanel(){
 if(proxyPanelLoading)return proxyPanelLoading;
 proxyPanelLoading=(async()=>{
 try{
  proxyPanel=await api('/api/proxies');
  const nodeRows=proxyPanel.nodes.map(n=>[n.name,n.name+(n.exit_ip?' · 最近 '+n.exit_ip:'')]);
  proxySelect($('#catalog-import-form').elements.front_node,nodeRows,'选择前置节点');
  proxySelect($('#catalog-bind-form').elements.node_name,nodeRows,'选择直出节点');
  proxySelect($('#catalog-bind-form').elements.proxy_id,proxyPanel.proxies.map(p=>[p.id,`${p.name} · ${p.gateway} · 经 ${p.front_node}`]),'选择已导入代理');
  $('#proxy-catalog-body').innerHTML=proxyPanel.proxies.map(p=>{
   const c=p.check||{};
   return `<tr><td><strong>${esc(p.name)}</strong><small>${esc(p.gateway)}</small></td><td>${esc(p.front_node)}<small>${p.refresh_ipfoxy?'IPFoxy 动态':'长效代理'}</small></td><td>${c.checked_at?(c.ok?badge('available'):badge('failed')):'待检测'}<small>${esc(c.exit_ip||c.error||'')}</small><small>${c.checked_at?stamp(c.checked_at)+' · '+num(c.elapsed_ms)+' ms':''}</small></td><td>${p.account_ids.map(i=>'#'+i).join('、')||'未绑定'}</td><td><button class="secondary mini" data-check-proxy="${p.id}">检测</button> <button class="secondary mini danger" data-delete-proxy="${p.id}" ${p.account_ids.length?'disabled':''}>删除</button></td></tr>`;
  }).join('')||empty(5);
  renderProxyAccounts();proxyMode();$('#updated').textContent='代理配置已更新';return true;
 }catch(err){notice(err.message);return false;}finally{proxyPanelLoading=null;}
 })();
 return proxyPanelLoading;
}
function editProxyAccount(id){
 const f=$('#catalog-bind-form'),a=proxyPanel.accounts.find(a=>a.id===id),b=a?.binding||{};
 f.elements.ids.value=String(id);
 f.elements.mode.value=b.mode==='catalog'?'catalog':'clash_pool';
 f.elements.node_name.value=b.node_name||'';f.elements.proxy_id.value=b.proxy_id||'';
 proxyMode();f.scrollIntoView({behavior:'smooth',block:'center'});
}
$('#catalog-bind-form').elements.mode.onchange=proxyMode;
$('#proxy-reload').onclick=loadProxyPanel;
$('#proxy-account-search').oninput=renderProxyAccounts;
$('#proxy-bind-selected').onclick=()=>{
 const ids=$$('[data-proxy-account]:checked').map(el=>el.dataset.proxyAccount);
 if(!ids.length){notice('请先选择账号');return;}
 const f=$('#catalog-bind-form');f.elements.ids.value=ids.join(',');f.scrollIntoView({behavior:'smooth',block:'center'});
};
$('#catalog-import-form').onsubmit=async event=>{
 event.preventDefault();const f=event.target,button=f.querySelector('[type=submit]');button.disabled=true;
 try{
  let text=f.elements.text.value.trim();const file=f.elements.file.files[0];
  if(file){if(file.size>256000)throw Error('文件不能超过 256 KB');if(text)throw Error('文件与粘贴内容请选择一种');text=await file.text();}
  const r=await api('/api/proxies/import',{text,front_node:f.elements.front_node.value,refresh_ipfoxy:f.elements.refresh_ipfoxy.checked});
  f.elements.text.value='';f.elements.file.value='';
  proxyNote('#proxy-import-result',`已新增 ${r.imported} 条，复用 ${r.existing} 条已有路线。`);await loadProxyPanel();
 }catch(err){proxyNote('#proxy-import-result',err.message);}finally{button.disabled=false;}
};
$('#catalog-bind-form').onsubmit=async event=>{
 event.preventDefault();const f=event.target,button=f.querySelector('[type=submit]');button.disabled=true;
 try{
  const v=values(f);
  if(v.mode==='clash_pool'&&!v.node_name)throw Error('请选择 Clash 节点');
  if(v.mode==='catalog'&&!v.proxy_id)throw Error('请选择海外代理');
  const r=await api('/api/accounts/proxy',v);proxyNote('#proxy-bind-result',`已更新 ${r.accounts.length} 个账号的出口，额度与冷却保留。`);await loadProxyPanel();
 }catch(err){proxyNote('#proxy-bind-result',err.message);}finally{button.disabled=false;}
};
function checkDescription(r){return r.ok?`出口正常：${r.exit_ip}，耗时 ${r.elapsed_ms} ms`:`检测失败：${r.error||r.error_type||'未知错误'}`;}
$('#proxy-test-selection').onclick=async event=>{
 const button=event.currentTarget;button.disabled=true;proxyNote('#proxy-bind-result','正在检测出口…');
 try{
  const f=$('#catalog-bind-form');
  const selection=f.elements.mode.value==='catalog'?{proxy_id:f.elements.proxy_id.value}:{node_name:f.elements.node_name.value};
  const result=await api('/api/proxies/check',selection);proxyNote('#proxy-bind-result',checkDescription(result));await loadProxyPanel();
 }catch(err){proxyNote('#proxy-bind-result',err.message);}finally{button.disabled=false;}
};
$('#tab-proxies').addEventListener('click',async event=>{
 const button=event.target.closest('button');if(!button)return;
 if(button.dataset.bindProxyAccount){editProxyAccount(Number(button.dataset.bindProxyAccount));return;}
 const id=button.dataset.checkProxy||button.dataset.deleteProxy;if(!id)return;
 button.disabled=true;
 try{
  if(button.dataset.checkProxy){notice('正在检测所选出口…');notice(checkDescription(await api('/api/proxies/check',{proxy_id:id})));}
  else{await api('/api/proxies/delete',{proxy_id:id});notice('已删除未绑定代理。');}
  await loadProxyPanel();
 }catch(err){notice(err.message);}finally{button.disabled=false;}
});
if(activeTab==='proxies')loadProxyPanel();
