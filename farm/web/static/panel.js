'use strict';
const $=s=>document.querySelector(s), $$=s=>Array.from(document.querySelectorAll(s));
const E={shopInfo:'店铺详情',productList:'主菜单',productRender:'补菜单（render）',productSpecifics:'定制菜品详情',homeShopList:'店铺列表',accountInfo:'账号信息'};
const ST={rejected:'最近请求被拒绝',paused:'账号已暂停',available:'可用',cooldown:'冷却',unknown:'待验证',needs_material:'本地构造未就绪',complete:'已完成',blocked:'已暂停',incomplete:'存在缺项',waiting:'等待账号 / 任务',queued:'排队',running:'运行中',stopped:'已停止',limit:'达到本轮上限',failed:'失败',interrupted:'进程中断',ready:'待运行'};
const D={eligible:'可领取任务',paused:'账号已暂停',identity_expired:'登录已失效',cooldown:'接口曾被拒绝，暂缓请求',recovery_probe_required:'冷却时间已到，需验证恢复',account_rest:'账号休息实验中',daily_budget_reached:'达到每日额度',missing_signing_device:'缺少签名设备数据',missing_user_id:'缺少用户 ID',missing_base_request:'缺少基础请求',unsupported_or_missing_endpoint_schema:'当前版本没有可用接口结构',local_construction_error:'本地构造失败，未发送',no_active_session:'没有活动会话',shop_job_required:'请选择店铺任务',menu_product_required:'需先采集主菜单取得菜品 ID',waiting_budget_or_already_probed:'当日已验证或额度不足',busy:'账号正在执行请求'};
Object.assign(D,{success:'业务数据验证成功',rejected:'请求被拒绝',transport_error:'网络请求失败',local_error:'本地构造失败',incomplete_payload:'数据不完整',busy_or_not_eligible:'账号忙或额度不足',local_batch_is_running:'本地采集正在运行，稍后探测',unfinished_probe_requires_reconciliation:'上次探测中断，需核对在途请求',account_state_requires_reconciliation:'本地会话与数据库暂停状态不一致，需对账',local_account_managed:'由本地批次管理，不能用旧数据库状态发请求',active_session_changed:'活动会话已变化，请刷新',local_ledger_unreadable:'本地账本无法读取，已阻止请求',missing_budget_policy:'没有配置此接口额度',shop_info_not_validated:'店铺详情未通过，后续未发送',menu_not_validated:'主菜单未通过，未发送 render',no_render_target:'菜单没有可测试菜品',skipped_closed:'闭店，跳过定制详情',open_state_unconfirmed:'未确认营业，跳过定制详情',no_custom_product:'没有定制菜品，跳过详情',cooldown_cleared:'已解除所选接口冷却；用量保留，未启动采集'});
const R={consecutive_cross_account_http403:'跨账号连续 403，采集已暂停',route_http403_cooldown:'出口连续 403，等待该出口暂停期结束；其他出口继续轮换',no_eligible_local_account_or_unresolved_coverage:'无可用账号或交付仍有缺项',database_unavailable:'等待数据库恢复，自动退避重试',no_eligible_account_or_work:'账号能力、额度或任务时间不满足',request_limit:'达到本轮请求上限',all_tasks_and_coverage_complete:'任务与完整度检查通过',unresolved_delivery_coverage:'交付仍有未解析缺项',user_stop:'手动停止',executor_restarted:'执行进程已重启',proxy_authentication_failed:'IPFoxy 代理认证失败（407），等待修正',network_unavailable:'连续网络失败，请修正代理后继续',transport_error:'网络请求失败，稍后重试'};
let state=null,activeTab='accounts';
const refreshing=new Set();
const loadedScopes=new Set();
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const stamp=s=>s?new Date(s).toLocaleString('zh-CN',{timeZone:'America/Sao_Paulo',hour12:false}):'—';
const num=n=>Number(n||0).toLocaleString('zh-CN');
const badge=s=>`<span class="badge ${['available','complete'].includes(s)?'good':['cooldown','failed','incomplete','blocked','rejected'].includes(s)?'bad':['running','waiting'].includes(s)?'waiting':''}">${esc(ST[s]||s||'待验证')}</span>`;
function effectiveCapability(a,endpoint){
 const database=state.capabilities.find(c=>c.account_id===a.id&&c.endpoint===endpoint)||{};
 const observation=(state.local_observations||[]).find(c=>c.account_id===a.id&&c.session_id===a.active_session_id&&c.endpoint===endpoint);
 const control=(state.account_controls||[]).find(c=>c.account_id===a.id&&c.endpoint===endpoint);
 let result={...database,source:'database'};
 if(observation&&(!result.observed_at||new Date(observation.observed_at)>new Date(result.observed_at)))result={...observation,http_status:observation.http};
 if(control){
  if(control.observed_at&&(!result.observed_at||new Date(control.observed_at)>=new Date(result.observed_at)))result={...result,...control,http_status:control.action==='manual_clear'?null:result.http_status};
  result.not_before=control.cooldown_until;result.rest_until=control.rest_until;result.rest_reason=control.rest_reason;
  if(control.cooldown_until)result.state='cooldown';
 }
 return result;
}
function accountCapabilities(a){
 return ['shopInfo','productList','productRender','productSpecifics'].map(endpoint=>{
  const c=effectiveCapability(a,endpoint);
  return `<small>${esc(E[endpoint])} ${badge(c.state)}${c.http_status?' · HTTP '+esc(c.http_status):''}</small><small>${c.not_before?'冷却至 '+stamp(c.not_before):'最近更新 '+stamp(c.observed_at)}${c.action==='manual_clear'?' · 手动解除，尚未验证':''}${c.rest_until?' · 账号仍休息至 '+stamp(c.rest_until):''}</small>`;
 }).join('');
}
const empty=n=>`<tr><td colspan="${n}" class="empty">暂无符合条件的数据</td></tr>`;
// The running server may retain an older Jinja template until its next restart.
$('#tab-accounts .section-head p').textContent='探测成功仅解除实际验证接口的冷却；手动解除不代表可用。用量统一累计，包含迁移的历史请求，解除冷却不清零额度，也不自动启动采集。';
$('#tab-accounts thead th:nth-child(4)').textContent='各接口最近观测';
function notice(message){$('#notice').textContent=message;$('#notice').hidden=false;}
async function api(path,body){const options=body===undefined?{}:{method:'POST',headers:{'X-Panel-CSRF':$('meta[name=csrf-token]').content},body:body instanceof FormData?body:JSON.stringify(body)};if(body!==undefined&&!(body instanceof FormData))options.headers['Content-Type']='application/json';const r=await fetch(path,options);const value=await r.json();if(!r.ok)throw Error(D[value.status]||D[value.error]||value.error||'操作失败');return value;}
function idsFilter(text){if(!text.trim())return null;const ids=new Set;for(const part of text.split(',')){const m=part.trim().match(/^([1-9]\d*)(?:\s*-\s*([1-9]\d*))?$/);if(!m)throw Error('账号范围格式应为 1,3,5-9');const lo=Number(m[1]),hi=Number(m[2]||m[1]);if(hi<lo||hi-lo>10000)throw Error('账号范围不合法');for(let x=lo;x<=hi;x++)ids.add(x);}return ids;}
function filteredAccounts(){const search=$('#filter-search').value.trim().toLowerCase(),ids=idsFilter($('#filter-ids').value),tags=$('#filter-tag').value.split(',').map(t=>t.trim().toLowerCase()).filter(Boolean),env=$('#filter-env').value;return state.accounts.filter(a=>(!search||[a.email,a.label,a.user_id].some(v=>String(v||'').toLowerCase().includes(search)))&&(!env||a.environment===env)&&(!ids||ids.has(a.id))&&(!tags.length||tags.some(t=>(a.tags||'').split(',').includes(t))));}
function render(){if(!state)return;const accounts=filteredAccounts(),ids=new Set(accounts.map(a=>a.id)),daily=state.daily.filter(r=>ids.has(r.account_id));const total=k=>daily.reduce((n,r)=>n+Number(r[k]||0),0);const active=state.executions.filter(r=>['queued','running'].includes(r.state)).length;
$('#metrics').innerHTML=[['已选账号',loadedScopes.has('accounts')?accounts.length:null,'按环境、范围与标签筛选'],['所选日请求',loadedScopes.has('accounts')?total('request_count'):null,'实际发送 + 中断待确认'],['有效数据',loadedScopes.has('accounts')?total('valid_data_count'):null,'按业务内容验证'],['运行 / 排队',loadedScopes.has('batches')?active:null,'批次自动保存与导出']].map(m=>`<div class="metric"><small>${m[0]}</small><b>${m[1]===null?'—':num(m[1])}</b><em>${m[2]}</em></div>`).join('');
$('#accounts-body').innerHTML=accounts.map(a=>{const rows=daily.filter(d=>d.account_id===a.id),count=k=>rows.reduce((n,r)=>n+Number(r[k]||0),0);return `<tr><td><strong>#${a.id} ${esc(a.label)}</strong><small>${esc(a.email||'邮箱尚未查询')}</small><small>${esc(a.user_id||'身份待补充')}</small>${a.identity_verified_at?'<small>身份验证成功 · '+stamp(a.identity_verified_at)+'</small>':''}</td><td>${badge(a.environment==='production'?'线上':'测试')}<small>${esc(a.tags||'未标记标签')}</small><small>出口：${esc(a.proxy_node||'已保存代理')}</small></td><td>${badge(a.observed_level)}${a.local_managed?badge('本地管理'):a.paused?badge('paused'):''}</td><td>${accountCapabilities(a)}</td><td><strong>${num(count('request_count'))} / ${num(count('valid_data_count'))}</strong></td><td>${stamp(a.last_request)}</td><td><small>成功 ${stamp(a.last_success)}</small><small>失败 ${stamp(a.last_failure)}</small></td><td><button class="secondary mini" data-account-proxy="${a.id}">代理 / 节点</button> <button class="secondary mini" data-probe="${a.id}">探测</button> <button class="secondary mini danger" data-delete-account="${a.id}">删除</button></td></tr>`;}).join('')||empty(8);
$('#daily-body').innerHTML=daily.map(r=>`<tr><td>#${r.account_id} ${esc(r.label)}</td><td>${E[r.endpoint]||esc(r.endpoint)}</td><td>${esc(({local_batch:'本地采集',local_probe:'本地探测',worker:'采集'})[r.origin]||r.origin)}</td><td>${num(r.request_count)}</td><td>${num(r.valid_data_count)}</td><td>${num(r.http_200_count)}</td><td>${num(r.http_403_count)}</td><td>${num(r.http_429_count)}</td><td>${num(r.business_error_count)}</td><td>${num(r.transport_error_count)} / ${num(r.local_error_count)}</td></tr>`).join('')||empty(10);
$('#caps-body').innerHTML=state.budgets.filter(b=>ids.has(b.account_id)).map(b=>{const a=accounts.find(a=>a.id===b.account_id),c=effectiveCapability(a,b.endpoint);return `<tr><td>#${b.account_id}</td><td>${E[b.endpoint]||esc(b.endpoint)}</td><td>${badge(c.state)}</td><td>${stamp(c.observed_at)}</td><td>${stamp(c.not_before)}${c.rest_until?'<small>账号休息至 '+stamp(c.rest_until)+'</small>':''}</td><td>${num(b.used_count)} / ${num(b.reserved_count)}</td><td>${num(b.work_limit)} / ${num(b.hard_limit)}<small>剩余 ${num(b.remaining_work)} / ${num(b.remaining_hard)}</small></td></tr>`;}).join('')||empty(7);
$('#batches-grid').innerHTML=state.runs.filter(r=>r.source_kind!=='probe'&&r.source_kind!=='validation').map(r=>`<article class="batch"><label class="check"><input type="checkbox" data-select-run="${r.id}">选择批次</label><small>BATCH #${r.id} · ${esc(r.source_kind)}</small><h3>${esc(r.label)}</h3>${badge(r.status)}<div class="progress"><i data-percent="${r.total?100*(Number(r.succeeded)+Number(r.skipped||0)+Number(r.covered||0))/r.total:0}"></i></div><small>${num(r.shops)} 家店 · 已生成 ${num(r.total)} 个请求任务</small><small>采集成功 ${num(r.succeeded)} · 详情补齐 ${num(r.covered||0)} · 闭店跳过 ${num(r.skipped)} · 未完成 ${num(Math.max(0,r.total-r.succeeded-(r.skipped||0)-(r.covered||0)-r.failed))} · 终止失败 ${num(r.failed)}</small><small>进度含详情补齐和按规则跳过；任务总数随菜单发现增加。重试中的任务计入未完成。</small><div class="batch-footer"><button class="secondary" data-export="${r.id}">导出当前结果</button><button class="secondary" data-failures="${r.id}">失败响应</button>${r.source_kind==='task_sheet'?`<button data-run="${r.id}">启动 / 继续</button>`:'<small>历史结果</small>'}<button class="secondary danger" data-delete-run="${r.id}">删除</button></div></article>`).join('')||'<div class="empty">还没有批次，导入任务表开始。</div>';
// CSP does not allow inline style; set progress widths as DOM properties.
if(!loadedScopes.has('batches'))$('#batches-grid').innerHTML='<div class="empty">正在读取任务批次…</div>';
$$('.batch .progress i').forEach((el,i)=>{el.style.width=el.dataset.percent+'%';});
$('#executions-body').innerHTML=state.executions.map(r=>`<tr><td>#${r.id} / 批次 ${r.run_id}</td><td>${r.environment==='production'?'线上':'测试'}<small>${esc(r.account_ids.join(', '))}</small><small>并发 ${num(r.selection?.concurrency||1)} · ${r.selection?.delay_scope==='productSpecifics'?'定制详情间隔':'每号间隔'} ${num(r.delay_seconds)} 秒</small></td><td>${badge(r.state)}</td><td>${num(r.sent)} / ${num(r.valid_count)}</td><td><small>${stamp(r.started_at)}</small><small>${stamp(r.finished_at)}</small></td><td>${esc(R[r.stop_reason]||r.stop_reason||'—')}${(r.export_summary?.account_diagnostics||[]).map(d=>`<small>#${d.account_id} ${E[d.endpoint]||''}：${esc(D[d.reason]||d.reason)}</small>`).join('')}</td><td>${(['running','queued'].includes(r.state)||((r.selection?.auto_resume||r.stop_reason==='database_unavailable')&&['waiting','interrupted'].includes(r.state)))?`<button data-stop="${r.id}" class="secondary mini">停止</button>`:r.export_summary?`<a class="button secondary mini" href="/downloads/execution-${r.id}">下载 ZIP</a><small>${r.export_summary.complete_shop_jobs} 完整 / ${r.export_summary.partial_shop_jobs} 缺项</small>`:''}</td></tr>`).join('')||empty(7);
}
function localWait(wait){
 if(!wait)return '';
 const reasons={account_cooldown:'等待账号冷却',daily_budget:'等待下一个业务日额度',network_backoff:'网络退避',task_retry:'等待任务重试',detail_interval:'等待定制详情间隔',requests_in_flight:'等待在途请求',ready:'正在调度'};
 return `<small>${esc(reasons[wait.reason]||wait.reason)} · ${stamp(new Date(wait.retry_at*1000).toISOString())} 自动继续</small>`;
}
let localRefreshing=false;
function renderLocalRuns(runs,unreadable=[]){
 const grid=$('#local-batches-grid');
 grid.innerHTML=runs.map(r=>`<article class="batch local-batch"><small>本地批次 · 仅保存在本机</small><h3>${esc(r.label)}</h3>${badge(r.state)}<small>${esc(r.id)}</small><div class="progress"><i data-percent="${r.shops?100*r.complete_shops/r.shops:0}"></i></div><small>完整 ${num(r.complete_shops)} / ${num(r.shops)} 家 · ${num(r.items)} 条菜品</small><small>已发送 ${num(r.sent)} 次 · 成功 ${num(r.success)} · HTTP 403 ${num(r.http403)}</small><small>闭店跳过 ${num(r.tasks.skipped_closed)} 个定制详情任务 · 不可售跳过 ${r.tasks.skipped_unavailable===undefined?'—':num(r.tasks.skipped_unavailable)} 个 · 待处理 ${num(r.tasks.pending+r.tasks.retry_wait+r.tasks.leased)}</small><small>并发 ${num(r.concurrency)} · ${r.delay_scope==='productSpecifics'?'定制详情间隔':'每号间隔'} ${num(r.delay_seconds)} 秒${r.delay_scope==='productSpecifics'?' · 普通接口无额外间隔':''}</small><small>${esc(R[r.stop_reason]||r.stop_reason||'按任务顺序采集')}</small>${localWait(r.waiting)}<small>最近进度：${stamp(r.updated_at)}</small><div class="batch-footer"><button class="secondary" data-local-run="${esc(r.id)}">店铺明细 / 请求日志</button>${r.downloads.includes('delivery.zip')?`<a class="button secondary" href="/downloads/local/${encodeURIComponent(r.id)}/delivery.zip">下载当前交付</a>`:''}</div></article>`).join('');
 if(unreadable.length)grid.insertAdjacentHTML('beforeend','<p>部分本地批次读取失败，请检查本地文件。</p>');
 grid.querySelectorAll('.progress i').forEach(el=>el.style.width=el.dataset.percent+'%');
}
async function refreshLocalRuns(){
 if(localRefreshing)return;localRefreshing=true;
 try{const r=await api('/api/local-runs');renderLocalRuns(r.runs,r.unreadable);}
 catch(e){$('#local-batches-grid').innerHTML='<p>本地批次读取失败，点击刷新重试。</p>';}
 finally{localRefreshing=false;}
}
async function showLocalRun(id){
 const dialog=$('#local-run-dialog'),body=$('#local-run-body');body.textContent='正在读取本地进度…';dialog.showModal();
 try{
  const r=await api('/api/local-runs/'+encodeURIComponent(id)),s=r.summary;
  const labels={succeeded:'成功',skipped_closed:'闭店跳过',skipped_unavailable:'不可售跳过',pending:'待处理',retry_wait:'等待重试',leased:'执行中',failed:'失败'};
  const taskText=tasks=>Object.entries(tasks||{}).map(([state,n])=>`${labels[state]||state} ${num(n)}`).join(' · ')||'尚未生成';
  body.innerHTML=`<p>${esc(s.label)} · 完整 ${num(s.complete_shops)} / ${num(s.shops)} 家 · ${esc(R[s.stop_reason]||s.stop_reason||ST[s.state]||s.state)}</p><p>当前设置：并发 ${num(s.concurrency)}，${s.delay_scope==='productSpecifics'?'仅定制详情':'每号'}间隔 ${num(s.delay_seconds)} 秒。已采结果仅保存在本机。</p><h3>店铺任务</h3><div class="table-wrap"><table><thead><tr><th>店铺</th><th>店铺详情</th><th>主菜单</th><th>render</th><th>定制详情</th></tr></thead><tbody>${r.shops.map(x=>`<tr><td>${esc(x.shop_id)}<small>${esc(x.name)}${x.closed?' · 闭店':''}</small></td>${['shopInfo','productList','productRender','productSpecifics'].map(ep=>`<td>${esc(taskText(x.tasks[ep]))}</td>`).join('')}</tr>`).join('')}</tbody></table></div><h3>最近 ${num(r.requests.length)} 次请求</h3><div class="table-wrap"><table><thead><tr><th>时间</th><th>账号</th><th>店铺 / 菜品</th><th>接口</th><th>HTTP</th><th>结果</th></tr></thead><tbody>${r.requests.map(x=>`<tr><td>${stamp(x.at)}</td><td>#${num(x.account_id)}</td><td>${esc(x.shop_id)}<small>${esc(x.target)}</small></td><td>${esc(E[x.endpoint]||x.endpoint)}</td><td>${esc(x.http??'—')}</td><td>${esc(({success:'成功',rejected:'拒绝',transport_error:'网络错误',local_error:'本地错误',store_closed:'闭店'})[x.outcome]||x.outcome)}</td></tr>`).join('')||empty(6)}</tbody></table></div>`;
 }catch(e){body.textContent='本地批次读取失败：'+e.message;}
}
document.addEventListener('click',e=>{const button=e.target.closest('[data-local-run]');if(button)showLocalRun(button.dataset.localRun);});

async function refresh(){
if(activeTab==='proxies'){if(typeof loadProxyPanel==='function')await loadProxyPanel();return;}
const scope=['batches','executions'].includes(activeTab)?'batches':'accounts';
if(scope==='batches')refreshLocalRuns();
const day=$('#stats-date').value,key=scope+':'+day;
if(refreshing.has(key))return;
refreshing.add(key);$('#updated').textContent='正在更新…';
try{
const query=new URLSearchParams({scope});if(day)query.set('date',day);
const update=await api('/api/state?'+query);
if($('#stats-date').value&&$('#stats-date').value!==update.business_date)return;
state=Object.assign({accounts:[],daily:[],budgets:[],capabilities:[],runs:[],executions:[]},state||{},update);
if(update.accounts)loadedScopes.add('accounts');if(update.runs)loadedScopes.add('batches');
if(!$('#stats-date').value)$('#stats-date').value=state.business_date;
if(update.statistics_sources?.unreadable?.length)notice('部分本地账本读取失败，当前合计不完整；已阻止使用不完整账本继续请求。');
render();$('#updated').textContent='数据时间 '+new Date(update.server_time).toLocaleTimeString('zh-CN');
}catch(e){notice(e.message);$('#updated').textContent='更新失败，可点击刷新重试';}
finally{refreshing.delete(key);}
}
function tab(name){activeTab=name;document.body.dataset.page=name;history.replaceState(null,'','#'+name);$$('.tab').forEach(e=>e.hidden=e.id!=='tab-'+name);$$('nav button').forEach(e=>e.classList.toggle('active',e.dataset.tab===name));$('#page-title').textContent=({accounts:'账号概览',daily:'每日统计',batches:'任务批次',executions:'运行记录',proxies:'代理管理'})[name];refresh();}
function values(form){return Object.fromEntries(new FormData(form));}
function bindForm(id,handler){$(id).addEventListener('submit',async e=>{e.preventDefault();const btn=e.target.querySelector('button[type=submit]');btn.disabled=true;try{const result=await handler(e.target);e.target.closest('dialog').close();notice(JSON.stringify(result,null,2));await refresh();}catch(err){notice(err.message);}finally{btn.disabled=false;}});}
$$('.endpoint-options').forEach(s=>s.innerHTML=Object.entries(E).map(([k,v])=>`<option value="${k}">${v}</option>`).join(''));
$('#run-endpoints').innerHTML=Object.entries(E).filter(([k])=>!['accountInfo','homeShopList'].includes(k)).map(([k,v])=>`<label class="check"><input type="checkbox" name="endpoints" value="${k}" checked>${v}</label>`).join('');
$$('[data-tab]').forEach(b=>b.onclick=()=>tab(b.dataset.tab));$$('[data-open]').forEach(b=>b.onclick=()=>{if(b.dataset.open==='proxy-dialog'){openProxyDialog();return;}$('#'+b.dataset.open).showModal();});$$('.close').forEach(b=>b.onclick=()=>b.closest('dialog').close());$('#refresh').onclick=refresh;$('#apply-filter').onclick=refresh;
document.addEventListener('click',async e=>{const b=e.target.closest('button');if(!b||b.closest('#probe-form'))return;try{if(b.dataset.failures){b.disabled=true;const result=await api('/api/requests/failures?run_id='+encodeURIComponent(b.dataset.failures));$('#failure-response-body').textContent=result.failures.length?result.failures.map(r=>`账号 #${r.account_id} · ${E[r.endpoint]||r.endpoint} · HTTP ${r.http_status||'无响应'} · ${r.started_at}\n${r.response?JSON.stringify(r.response,null,2):'这次历史失败尚未保存响应体。'}`).join('\n\n'):'此批次暂无失败记录';$('#failure-response-dialog').showModal();}if(b.dataset.accountProxy){openProxyDialog(Number(b.dataset.accountProxy));}if(b.dataset.deleteAccount){await removeAccounts([Number(b.dataset.deleteAccount)]);}if(b.dataset.deleteRun){await removeRuns([Number(b.dataset.deleteRun)]);}if(b.dataset.run){const f=$('#run-form');f.elements.run_id.value=b.dataset.run;f.elements.environment.value=$('#filter-env').value||'test';f.elements.ids.value=$('#filter-ids').value;f.elements.tags.value=$('#filter-tag').value;$('#run-title').textContent='#'+b.dataset.run;$('#selected-accounts').textContent='可预览实际匹配账号';$('#run-dialog').showModal();}if(b.dataset.probe){$('#probe-form').elements.account_id.value=b.dataset.probe;$('#probe-form').elements.endpoint.value='accountInfo';$('#probe-result').textContent='请选择接口。身份验证不能代表 render 或定制详情可用。';$('#probe-dialog').showModal();}if(b.dataset.stop){b.disabled=true;await api('/api/executions/'+b.dataset.stop+'/stop',{});await refresh();}if(b.dataset.export){b.disabled=true;notice('正在生成交付表和完整度报告…');const r=await api('/api/runs/'+b.dataset.export+'/export',{});notice(`导出完成：${r.summary.shops} 家店，${r.summary.items} 条菜品。完整 ${r.summary.complete_shop_jobs} 家，缺项 ${r.summary.partial_shop_jobs} 家。`);location.href=r.download;}}catch(err){notice(err.message);}finally{b.disabled=false;}});
$('#preview-accounts').onclick=async()=>{try{const r=await api('/api/accounts/select',values($('#run-form')));$('#selected-accounts').textContent=r.accounts.length?r.accounts.map(a=>`#${a.id} ${a.label}${a.paused?'（暂停）':''}`).join('、'):'没有匹配账号';}catch(e){notice(e.message);}};
bindForm('#import-form',async f=>{const r=await api('/api/accounts/import',new FormData(f));f.reset();return r;});
bindForm('#profile-form',f=>{const v=values(f);if(v.paused==='')delete v.paused;else v.paused=v.paused==='true';return api('/api/accounts/profile',v);});
async function openProxyDialog(accountId){
 const ids=accountId?String(accountId):(state?filteredAccounts().map(a=>a.id).join(','):'');
 if(!await loadProxyPanel())return;
 tab('proxies');
 if(accountId)editProxyAccount(accountId);
 else $('#catalog-bind-form').elements.ids.value=ids;
}
bindForm('#budget-form',f=>api('/api/budgets',values(f)));
bindForm('#tasks-form',async f=>{const r=await api('/api/tasks/import',new FormData(f));tab('batches');return r;});
bindForm('#run-form',async f=>{const v=values(f);v.endpoints=new FormData(f).getAll('endpoints');if(!v.endpoints.length)throw Error('请至少选择一个接口');const r=await api('/api/executions',v);tab('executions');return r;});
$('#probe-form').elements.endpoint.insertAdjacentHTML('beforeend','<option value="shopFlow">店铺四接口检查（最多 4 次）</option>');
async function probeAction(clear=false){
 const f=$('#probe-form'),buttons=f.querySelectorAll('button:not(.close)'),result=$('#probe-result');
 const v=values(f);if(!v.shop_id)delete v.shop_id;
 if(clear&&v.endpoint==='shopFlow'){result.textContent='手动解除请先选择一个具体接口。';return;}
 buttons.forEach(b=>b.disabled=true);
 result.textContent=clear?'正在解除所选接口冷却…':'正在验证… 每个接口最多发送 1 次，render / 定制详情会先请求必要的店铺与菜单数据。';
 try{
  const r=await api(clear?'/api/accounts/cooldown/clear':'/api/probe',v);
  result.textContent=clear?D.cooldown_cleared:`实际发送 ${r.sent} 次；已验证 ${r.verified.map(e=>E[e]).join('、')||'无'}。\n`+r.results.map(x=>`${E[x.endpoint]}：${x.sent?'已发送':'未发送'} · ${D[x.status]||x.status}${x.http?' · HTTP '+x.http:''}${x.cooldown_cleared?' · 已解除该接口冷却':''}`).join('\n');
  await refresh();
 }catch(err){result.textContent=err.message;}finally{buttons.forEach(b=>b.disabled=false);}
}
$('#probe-form').onsubmit=e=>{e.preventDefault();probeAction();};
$('#clear-cooldown').onclick=()=>probeAction(true);
$('#validate-accounts').onclick=async e=>{const b=e.target;b.disabled=true;try{notice('正在按当前筛选顺序验证账号信息…');const r=await api('/api/accounts/validate',{environment:$('#filter-env').value,ids:$('#filter-ids').value,tags:$('#filter-tag').value});notice(`身份验证：选中 ${r.selected_count} 个，发送 ${r.sent} 次，验证成功 ${r.verified} 个。\n`+r.results.map(x=>`#${x.account_id}：${x.outcome==='success'?'身份有效':D[x.status]||x.outcome||x.status}${x.http?'，HTTP '+x.http:''}`).join('\n'));await refresh();}catch(err){notice(err.message);}finally{b.disabled=false;}};
async function removeAccounts(ids){
 if(!ids.length)throw Error('没有选中账号');
 if(!confirm(`永久删除 ${ids.length} 个账号（#${ids.join(', #')}）及其登录凭据？已采集结果保留，账号请求历史会删除。`))return;
 const result=await api('/api/accounts/delete',{ids});notice(`已删除 ${result.deleted_accounts.length} 个账号，保留 ${result.preserved_results} 条采集结果。`);await refresh();
}
async function removeRuns(ids){
 if(!ids.length)throw Error('请先勾选批次');
 if(!confirm(`永久删除 ${ids.length} 个批次（#${ids.join(', #')}）及其任务、结果和运行记录？账号与已消耗额度保留。`))return;
 const result=await api('/api/runs/delete',{ids});notice(`已删除 ${result.deleted_runs.length} 个批次。`);await refresh();
}
$('#delete-accounts').onclick=async()=>{try{await removeAccounts(filteredAccounts().map(a=>a.id));}catch(e){notice(e.message);}};
$('#delete-batches').onclick=async()=>{try{await removeRuns($$('[data-select-run]:checked').map(el=>Number(el.dataset.selectRun)));}catch(e){notice(e.message);}};
tab(['accounts','daily','batches','executions','proxies'].includes(location.hash.slice(1))?location.hash.slice(1):'accounts');setInterval(()=>{if(!document.hidden&&!document.querySelector('dialog[open]'))refresh();},15000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});

api('/api/proxy-settings').then(p=>{$('#proxy-summary').textContent=p.configured?'默认出口：'+p.gateway+(p.front_proxy_enabled?'（经过前置代理）':'')+(p.refresh_ipfoxy?'，已启用 IPFoxy 刷新':''):'尚未配置默认出口，请填写后保存。';}).catch(()=>{});


$('#filter-search').addEventListener('input',()=>{if(state)render();});
