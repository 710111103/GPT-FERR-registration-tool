package api

import "fmt"

// fallbackPage 在没有内嵌前端时返回的最小可用页面。
// 生产构建会把 Python 版的 index.html 打进二进制；开发期用这个页面能验证所有 API。
func fallbackPage(name, version string) string {
	if name == "login.html" {
		return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>登录 · Turb GPT</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0f1115;color:#e6e8eb;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#181b22;padding:32px 36px;border-radius:12px;border:1px solid #262b35;width:320px}
h1{font-size:18px;margin:0 0 20px;font-weight:600}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #2f3542;
background:#0f1115;color:#e6e8eb;font-size:14px;margin-bottom:14px}
button{width:100%;padding:10px;border-radius:8px;border:0;background:#4f7cff;color:#fff;
font-size:14px;font-weight:600;cursor:pointer}
button:hover{background:#3f6bea}
.err{color:#ff6b6b;font-size:13px;min-height:18px}
</style></head>
<body><form class="card" id="f">
<h1>Turb GPT Register</h1>
<input id="code" type="password" placeholder="授权码" autofocus>
<div class="err" id="err"></div>
<button type="submit">登录</button>
</form>
<script>
document.getElementById('f').onsubmit = async (e) => {
  e.preventDefault();
  const code = document.getElementById('code').value;
  const r = await fetch('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({code})});
  const j = await r.json();
  if (j.ok) location.href = '/'; else document.getElementById('err').textContent = j.error || '登录失败';
};
</script></body></html>`
	}

	return fmt.Sprintf(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>Turb GPT Register</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0f1115;color:#e6e8eb;margin:0}
header{padding:16px 24px;border-bottom:1px solid #262b35;display:flex;justify-content:space-between;align-items:center}
h1{font-size:16px;margin:0;font-weight:600}
.tag{font-size:12px;color:#8b94a3}
main{padding:24px;display:grid;gap:20px;grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
.card{background:#181b22;border:1px solid #262b35;border-radius:12px;padding:18px}
.card h2{font-size:13px;margin:0 0 14px;color:#8b94a3;font-weight:600;letter-spacing:.04em}
.kv{display:flex;justify-content:space-between;padding:6px 0;font-size:14px;border-bottom:1px solid #1f242d}
.kv:last-child{border-bottom:0}
.kv span:last-child{font-variant-numeric:tabular-nums}
input,select,button{font-family:inherit;font-size:14px}
input,select{width:100%%;box-sizing:border-box;padding:8px 10px;border-radius:8px;border:1px solid #2f3542;
background:#0f1115;color:#e6e8eb;margin-bottom:10px}
button{padding:9px 16px;border-radius:8px;border:0;background:#4f7cff;color:#fff;font-weight:600;cursor:pointer;width:100%%}
button:hover{background:#3f6bea}
pre{background:#0f1115;border:1px solid #262b35;border-radius:8px;padding:12px;font-size:12px;
max-height:260px;overflow:auto;margin:0;white-space:pre-wrap}
</style></head>
<body>
<header><h1>Turb GPT Register</h1><span class="tag">Go %s</span></header>
<main>
  <div class="card"><h2>概览</h2><div id="summary"></div></div>
  <div class="card"><h2>启动注册</h2>
    <input id="count" type="number" value="1" min="1" placeholder="数量">
    <input id="workers" type="number" value="2" min="1" max="16" placeholder="并发数">
    <button onclick="submitJobs()">开始注册</button>
    <div id="submitMsg" class="tag" style="margin-top:10px"></div>
  </div>
  <div class="card"><h2>能力</h2><div id="caps"></div></div>
</main>
<script>
const fmt = (n) => (n==null?'-':n.toLocaleString());
async function api(path, opt) {
  const r = await fetch(path, opt);
  if (r.status === 401) { location.href='/login'; throw new Error('unauthorized'); }
  return r.json();
}
async function refresh() {
  const s = await api('/api/summary');
  document.getElementById('summary').innerHTML =
    '<div class="kv"><span>账号</span><span>'+fmt(s.accounts)+'</span></div>'+
    '<div class="kv"><span>邮箱可用</span><span>'+fmt(s.outlook_available)+'</span></div>'+
    '<div class="kv"><span>邮箱已用</span><span>'+fmt(s.outlook_used)+'</span></div>'+
    '<div class="kv"><span>运行中任务</span><span>'+fmt(s.active_jobs)+'</span></div>'+
    '<div class="kv"><span>并发上限</span><span>'+fmt(s.workers)+'</span></div>';
}
async function loadCaps() {
  const c = await api('/api/capabilities');
  const list = c.drivers.map(d => '<div class="kv"><span>'+d.name+'</span><span>'+
    (d.available?'可用':'未移植')+'</span></div>').join('');
  document.getElementById('caps').innerHTML = list +
    '<div class="kv"><span>邮箱来源</span><span>'+(c.mail_sources||[]).join(', ')+'</span></div>'+
    '<div class="kv"><span>Sentinel</span><span>'+c.sentinel_solver+'</span></div>';
}
async function submitJobs() {
  const count = +document.getElementById('count').value;
  const workers = +document.getElementById('workers').value;
  const j = await api('/api/jobs/submit', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({count, workers})});
  document.getElementById('submitMsg').textContent =
    j.ok ? ('已提交 '+j.job_ids.length+' 个任务，并发 '+j.workers) : (j.error||'提交失败');
  refresh();
}
refresh(); loadCaps(); setInterval(refresh, 5000);
</script></body></html>`, version)
}
