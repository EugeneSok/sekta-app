// Sekta — Cloudflare Worker: GitHub OAuth gate + download page
//
// Env vars (wrangler.toml [vars]):
//   ALLOWED_USERS   — comma-separated GitHub logins: "alice,bob,charlie"
//   GITHUB_CLIENT_ID
//
// Secrets (wrangler secret put <NAME>):
//   GITHUB_CLIENT_SECRET
//   SESSION_SECRET   — random 32+ char string (openssl rand -hex 32)

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/auth/login')    return handleLogin(url, env);
    if (url.pathname === '/auth/callback') return handleCallback(request, url, env);
    if (url.pathname === '/auth/logout')   return handleLogout();
    if (url.pathname === '/logo.png')      return fetchLogo();

    return handlePage(request, url, env);
  },
};

// ── Routes ────────────────────────────────────────────────────────────────────

function handleLogin(url, env) {
  const state = crypto.randomUUID();
  const params = new URLSearchParams({
    client_id:    env.GITHUB_CLIENT_ID,
    redirect_uri: `${url.origin}/auth/callback`,
    scope:        'read:user',
    state,
  });
  return new Response(null, {
    status: 302,
    headers: {
      Location:   `https://github.com/login/oauth/authorize?${params}`,
      'Set-Cookie': cookie('oauth_state', state, 600),
    },
  });
}

async function handleCallback(request, url, env) {
  const code  = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const saved = parseCookies(request).oauth_state;

  if (!code || !state || state !== saved) {
    return htmlResponse(errorPage('Невірний стан авторизації.'), 400);
  }

  // Exchange code → token
  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id:     env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri:  `${url.origin}/auth/callback`,
    }),
  });
  const { access_token } = await tokenRes.json();
  if (!access_token) return htmlResponse(errorPage('GitHub не надав токен.'), 401);

  // Get GitHub username
  const userRes = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${access_token}`, 'User-Agent': 'sekta-app' },
  });
  const { login } = await userRes.json();

  // Check allowlist
  const allowed = (env.ALLOWED_USERS || '').split(',').map(u => u.trim().toLowerCase());
  if (!allowed.includes(login.toLowerCase())) {
    return htmlResponse(deniedPage(login), 403);
  }

  // Issue session cookie
  const token = await sign({ login, exp: Date.now() + 30 * 86400_000 }, env.SESSION_SECRET);
  return new Response(null, {
    status: 302,
    headers: {
      Location:   '/',
      'Set-Cookie': [
        cookie('sekta_session', token, 30 * 86400),
        cookie('oauth_state', '', 0),         // clear state
      ].join(', '),
    },
  });
}

function handleLogout() {
  return new Response(null, {
    status: 302,
    headers: {
      Location:   '/',
      'Set-Cookie': cookie('sekta_session', '', 0),
    },
  });
}

async function handlePage(request, url, env) {
  const sessionToken = parseCookies(request).sekta_session;
  if (!sessionToken) return htmlResponse(loginPage(url));

  const payload = await verify(sessionToken, env.SESSION_SECRET);
  if (!payload) return htmlResponse(loginPage(url));

  // Re-check allowlist in case user was removed
  const allowed = (env.ALLOWED_USERS || '').split(',').map(u => u.trim().toLowerCase());
  if (!allowed.includes(payload.login.toLowerCase())) {
    return htmlResponse(deniedPage(payload.login), 403);
  }

  return htmlResponse(mainPage(payload.login));
}

// Proxy the logo from the sekta-app releases repo
async function fetchLogo() {
  const res = await fetch(
    'https://raw.githubusercontent.com/EugeneSok/sekta-app/main/docs/logo.png',
    { cf: { cacheTtl: 86400 } },
  );
  return new Response(res.body, {
    headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' },
  });
}

// ── HMAC-SHA256 session ───────────────────────────────────────────────────────

async function getKey(secret) {
  return crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'],
  );
}

async function sign(payload, secret) {
  const data = btoa(JSON.stringify(payload));
  const key  = await getKey(secret);
  const sig  = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verify(token, secret) {
  try {
    const [data, sigB64] = token.split('.');
    const key = await getKey(secret);
    const sig = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
    const ok  = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(data));
    if (!ok) return null;
    const payload = JSON.parse(atob(data));
    return Date.now() < payload.exp ? payload : null;
  } catch { return null; }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseCookies(request) {
  return Object.fromEntries(
    (request.headers.get('Cookie') || '')
      .split(';')
      .map(c => c.trim().split('=').map(s => decodeURIComponent(s.trim() || ''))),
  );
}

function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

function htmlResponse(body, status = 200) {
  return new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ── HTML pages ────────────────────────────────────────────────────────────────

const BASE_CSS = `
  :root{--bg0:#0B0F14;--bg1:#0F1419;--bg2:#161B22;--bg-elev:#1A1E26;
    --border:#2A3040;--border-soft:#1A2030;--text:#E2E8F0;--text-dim:#94A3B8;
    --text-muted:#64748B;--accent:#2563EB;--green:#16A34A;--red:#DC2626;--yellow:#F59E0B;}
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  html{scroll-behavior:smooth;}
  body{background:var(--bg1);color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Inter',sans-serif;
    min-height:100vh;display:flex;flex-direction:column;align-items:center;overflow-x:hidden;}
  #topo{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:0;}
  @keyframes pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:.6;transform:scale(1.08);}}
  @keyframes spin{to{transform:rotate(360deg);}}
  @keyframes blink{0%,100%{opacity:1;}50%{opacity:.3;}}
`;

const TOPO_JS = `
(function(){
  const cv=document.getElementById('topo'),cx=cv.getContext('2d');
  const b=Array.from({length:256},(_,i)=>i);let s=12345;
  const r=()=>{s=(Math.imul(s,1664525)+1013904223)|0;return(s>>>0)/0x100000000;};
  for(let i=255;i>0;i--){const j=Math.floor(r()*(i+1));[b[i],b[j]]=[b[j],b[i]];}
  const P=[...b,...b];
  const fd=t=>t*t*t*(t*(t*6-15)+10),lp=(a,b,t)=>a+t*(b-a);
  const gr=(h,x,y)=>{const v=h&3,u=v<2?x:y,w=v<2?y:x;return((h&1)?-u:u)+((h&2)?-w:w);};
  function ns(xi,yi){
    const X=Math.floor(xi)&255,Y=Math.floor(yi)&255,xf=xi-Math.floor(xi),yf=yi-Math.floor(yi);
    const u=fd(xf),v=fd(yf),a=P[X]+Y,bb=P[X+1]+Y;
    return lp(lp(gr(P[a],xf,yf),gr(P[bb],xf-1,yf),u),lp(gr(P[a+1],xf,yf-1),gr(P[bb+1],xf-1,yf-1),u),v);
  }
  function fbm(x,y){let v=0,a=1,f=1,m=0;for(let i=0;i<3;i++){v+=a*ns(x*f+22.8,y*f+15.1);m+=a;a*=.45;f*=1.7;}return v/m;}
  function el(nx,ny){return Math.max(0,Math.min(1,(fbm(nx,ny)+.8)/1.2));}
  function draw(){
    const W=innerWidth,H=innerHeight;cv.width=W;cv.height=H;
    cx.fillStyle='#0F1419';cx.fillRect(0,0,W,H);
    const gx=120,gy=Math.max(160,Math.round(H/W*gx)),g=new Float32Array((gx+1)*(gy+1));
    for(let j=0;j<=gy;j++)for(let i=0;i<=gx;i++)g[j*(gx+1)+i]=el(i/gx,j/gy);
    const cw=W/gx,ch=H/gy;
    for(let l=1;l<22;l++){
      const t=l/22,iI=l%5===0;cx.beginPath();
      cx.strokeStyle=\`rgba(37,99,235,\${iI?.55:.28})\`;cx.lineWidth=iI?1.5:.9;
      for(let j=0;j<gy;j++){for(let i=0;i<gx;i++){
        const v00=g[j*(gx+1)+i],v10=g[j*(gx+1)+i+1],v01=g[(j+1)*(gx+1)+i],v11=g[(j+1)*(gx+1)+i+1];
        const x=i*cw,y=j*ch,lr=(a,b)=>b===a?0:(t-a)/(b-a),pts=[];
        if((v00>t)!==(v10>t))pts.push([x+lr(v00,v10)*cw,y]);
        if((v10>t)!==(v11>t))pts.push([x+cw,y+lr(v10,v11)*ch]);
        if((v01>t)!==(v11>t))pts.push([x+lr(v01,v11)*cw,y+ch]);
        if((v00>t)!==(v01>t))pts.push([x,y+lr(v00,v01)*ch]);
        if(pts.length>=2){cx.moveTo(pts[0][0],pts[0][1]);cx.lineTo(pts[1][0],pts[1][1]);}
        if(pts.length===4){cx.moveTo(pts[2][0],pts[2][1]);cx.lineTo(pts[3][0],pts[3][1]);}
      }}cx.stroke();
    }
    cx.setLineDash([2,10]);cx.strokeStyle='rgba(37,99,235,0.11)';cx.lineWidth=.5;
    for(let n=1;n<=3;n++){
      cx.beginPath();cx.moveTo(W*n/4,0);cx.lineTo(W*n/4,H);cx.stroke();
      cx.beginPath();cx.moveTo(0,H*n/4);cx.lineTo(W,H*n/4);cx.stroke();
    }
    cx.setLineDash([]);
  }
  draw();addEventListener('resize',()=>{clearTimeout(window._t);window._t=setTimeout(draw,150);});
})();
`;

function loginPage(url) {
  return `<!DOCTYPE html><html lang="uk"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sekta — Вхід</title><link rel="icon" type="image/png" href="/logo.png">
<style>
${BASE_CSS}
.wrap{position:relative;z-index:1;display:flex;flex-direction:column;align-items:center;
  justify-content:center;min-height:100vh;padding:24px;}
.logo-wrap{position:relative;margin-bottom:28px;}
.logo-wrap::before{content:'';position:absolute;inset:-20px;border-radius:50%;
  background:radial-gradient(circle,rgba(37,99,235,.2) 0%,transparent 70%);
  animation:pulse 3s ease-in-out infinite;}
.logo-wrap img{width:80px;height:80px;border-radius:18px;position:relative;
  box-shadow:0 0 40px rgba(37,99,235,.3),0 8px 24px rgba(0,0,0,.6);}
h1{font-size:28px;font-weight:800;letter-spacing:-.03em;margin-bottom:6px;
  background:linear-gradient(135deg,var(--text) 0%,var(--text-dim) 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.sub{font-size:14px;color:var(--text-muted);margin-bottom:40px;}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:16px;
  padding:28px;width:100%;max-width:340px;display:flex;flex-direction:column;gap:16px;}
.hint{font-size:13px;color:var(--text-muted);text-align:center;line-height:1.5;}
.btn-gh{display:flex;align-items:center;justify-content:center;gap:10px;
  background:#24292f;color:#fff;text-decoration:none;border-radius:10px;
  padding:13px 20px;font-size:15px;font-weight:600;transition:background .18s,transform .12s;
  border:1px solid rgba(255,255,255,.1);}
.btn-gh:hover{background:#32383f;}
.btn-gh:active{transform:scale(.97);}
</style></head><body>
<canvas id="topo"></canvas>
<div class="wrap">
  <div class="logo-wrap"><img src="/logo.png" alt="Sekta"></div>
  <h1>Sekta</h1>
  <div class="sub">Внутрішній реліз — потрібна авторизація</div>
  <div class="card">
    <div class="hint">Увійди через GitHub щоб отримати доступ до завантажень.</div>
    <a class="btn-gh" href="/auth/login">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
      </svg>
      Увійти через GitHub
    </a>
  </div>
</div>
<script>${TOPO_JS}</script>
</body></html>`;
}

function mainPage(login) {
  return `<!DOCTYPE html><html lang="uk"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sekta — Завантаження</title><link rel="icon" type="image/png" href="/logo.png">
<style>
${BASE_CSS}
.page{position:relative;z-index:1;width:100%;max-width:960px;padding:0 24px;
  display:flex;flex-direction:column;align-items:center;}
header{width:100%;display:flex;align-items:center;justify-content:space-between;padding:24px 0 0;}
.brand{display:flex;align-items:center;gap:10px;text-decoration:none;}
.brand img{width:32px;height:32px;border-radius:8px;}
.brand-name{font-size:18px;font-weight:700;color:var(--text);letter-spacing:-.02em;}
.user-pill{display:flex;align-items:center;gap:8px;}
.gh-avatar{width:28px;height:28px;border-radius:50%;border:1px solid var(--border);}
.gh-login{font-size:13px;color:var(--text-dim);}
.btn-logout{display:flex;align-items:center;gap:6px;background:none;
  border:1px solid var(--border);border-radius:8px;padding:6px 12px;
  color:var(--text-muted);font-size:13px;font-weight:500;cursor:pointer;
  font-family:inherit;transition:border-color .2s,color .2s;text-decoration:none;}
.btn-logout:hover{border-color:var(--text-muted);color:var(--text-dim);}
.hero{display:flex;flex-direction:column;align-items:center;text-align:center;padding:64px 0 48px;}
.logo-wrap{position:relative;margin-bottom:22px;}
.logo-wrap::before{content:'';position:absolute;inset:-20px;border-radius:50%;
  background:radial-gradient(circle,rgba(37,99,235,.22) 0%,transparent 70%);
  animation:pulse 3s ease-in-out infinite;}
.logo-wrap img{width:88px;height:88px;border-radius:20px;position:relative;
  box-shadow:0 0 40px rgba(37,99,235,.35),0 8px 32px rgba(0,0,0,.6);}
.hero h1{font-size:44px;font-weight:800;letter-spacing:-.04em;
  background:linear-gradient(135deg,var(--text) 0%,var(--text-dim) 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:10px;}
.hero p{font-size:15px;color:var(--text-dim);max-width:400px;line-height:1.6;margin-bottom:20px;}
.vbadge{display:inline-flex;align-items:center;gap:6px;background:var(--bg2);
  border:1px solid var(--border);border-radius:20px;padding:5px 14px;
  font-size:13px;color:var(--text-dim);font-family:'SF Mono','Fira Code',monospace;}
.vdot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:blink 2s ease-in-out infinite;}
.cards{width:100%;display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:64px;}
@media(max-width:680px){.cards{grid-template-columns:1fr;}.hero h1{font-size:32px;}}
@media(max-width:900px) and (min-width:681px){.cards{grid-template-columns:repeat(2,1fr);}}
.card{background:rgba(22,27,34,.82);border:1px solid var(--border);border-radius:16px;
  padding:26px 22px 22px;display:flex;flex-direction:column;gap:14px;
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  transition:border-color .2s,transform .2s,box-shadow .2s;}
.card:hover{border-color:rgba(37,99,235,.5);transform:translateY(-3px);
  box-shadow:0 16px 40px rgba(0,0,0,.4),0 0 0 1px rgba(37,99,235,.1);}
.ci{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;}
.ci svg{width:28px;height:28px;}
.ci.win{background:rgba(37,99,235,.15);}.ci.and{background:rgba(22,163,74,.15);}.ci.mac{background:rgba(148,163,184,.1);}
.ct{font-size:17px;font-weight:700;color:var(--text);letter-spacing:-.01em;}
.cd{font-size:13px;color:var(--text-muted);line-height:1.5;flex:1;}
.cn{font-size:11px;color:var(--text-muted);background:var(--bg0);
  border:1px solid var(--border-soft);border-radius:6px;padding:6px 10px;line-height:1.4;}
.cn span{color:var(--yellow);font-weight:600;}
.btn-dl{display:flex;align-items:center;justify-content:center;gap:8px;
  background:var(--accent);color:#fff;text-decoration:none;border-radius:10px;
  padding:11px 20px;font-size:14px;font-weight:600;transition:background .18s,transform .12s;}
.btn-dl:hover{background:#1d4ed8;}.btn-dl:active{transform:scale(.97);}
.btn-dl.loading{background:var(--bg-elev);color:var(--text-muted);pointer-events:none;}
.fsz{font-size:11px;color:var(--text-muted);text-align:center;margin-top:-6px;}
.spinner{width:15px;height:15px;border:2px solid rgba(255,255,255,.25);border-top-color:#fff;
  border-radius:50%;animation:spin .7s linear infinite;display:inline-block;flex-shrink:0;}
.divider{width:100%;height:1px;background:linear-gradient(to right,transparent,var(--border),transparent);margin-bottom:28px;}
footer{padding:0 0 36px;font-size:13px;color:var(--text-muted);
  display:flex;flex-direction:column;align-items:center;gap:6px;}
footer a{color:var(--text-muted);text-decoration:none;transition:color .2s;}
footer a:hover{color:var(--text-dim);}
</style></head><body>
<canvas id="topo"></canvas>
<div class="page">
  <header>
    <a href="/" class="brand">
      <img src="/logo.png" alt="Sekta">
      <span class="brand-name">Sekta</span>
    </a>
    <div class="user-pill">
      <img class="gh-avatar" src="https://github.com/${login}.png?size=56" alt="${login}">
      <span class="gh-login">${login}</span>
      <a class="btn-logout" href="/auth/logout">Вийти</a>
    </div>
  </header>

  <section class="hero">
    <div class="logo-wrap"><img src="/logo.png" alt="Sekta"></div>
    <h1>Sekta</h1>
    <p>Захищений моніторинг мережі. Один застосунок — Windows, Android та macOS.</p>
    <div class="vbadge"><div class="vdot"></div><span id="ver">Завантаження...</span></div>
  </section>

  <div class="cards">
    <div class="card">
      <div class="ci win">
        <svg viewBox="0 0 24 24" fill="none">
          <path d="M3 5.6L10.5 4.5V11.5H3V5.6Z" fill="#2563EB"/>
          <path d="M11.5 4.35L21 3V11.5H11.5V4.35Z" fill="#2563EB"/>
          <path d="M3 12.5H10.5V19.5L3 18.4V12.5Z" fill="#2563EB"/>
          <path d="M11.5 12.5H21V21L11.5 19.65V12.5Z" fill="#2563EB"/>
        </svg>
      </div>
      <div><div class="ct">Windows</div>
        <div class="cd">ZIP-архів. Розпакуй та запусти <code style="color:var(--text-dim);font-size:12px">Sekta.exe</code>. Потребує Windows 10/11 та WebView2 Runtime.</div>
      </div>
      <div class="cn"><span>⚠</span> Якщо Windows блокує — «Детальніше» → «Запустити».</div>
      <a id="dl-windows" class="btn-dl loading" href="#" target="_blank">
        <span class="spinner" id="sp-windows"></span><span id="lbl-windows">Завантаження...</span>
      </a>
      <div class="fsz" id="sz-windows"></div>
    </div>

    <div class="card">
      <div class="ci and">
        <svg viewBox="0 0 24 24" fill="none">
          <path d="M6 18C6 18.55 6.45 19 7 19H8V22C8 22.55 8.45 23 9 23S10 22.55 10 22V19H14V22C14 22.55 14.45 23 15 23S16 22.55 16 22V19H17C17.55 19 18 18.55 18 18V9H6V18ZM3.5 9C2.67 9 2 9.67 2 10.5V17.5C2 18.33 2.67 19 3.5 19S5 18.33 5 17.5V10.5C5 9.67 4.33 9 3.5 9ZM20.5 9C19.67 9 19 9.67 19 10.5V17.5C19 18.33 19.67 19 20.5 19S22 18.33 22 17.5V10.5C22 9.67 21.33 9 20.5 9ZM15.53 2.16L16.84.85C17.03.66 17.03.38 16.84.19 16.65 0 16.37 0 16.18.19L14.7 1.67C13.83 1.25 12.94 1 12 1S10.17 1.25 9.3 1.67L7.82.19C7.63 0 7.35 0 7.16.19 6.97.38 6.97.66 7.16.85L8.47 2.16C6.97 3.07 6 4.62 6 6.5V7H18V6.5C18 4.62 17.03 3.07 15.53 2.16ZM10 5H9V4H10V5ZM15 5H14V4H15V5Z" fill="#16A34A"/>
        </svg>
      </div>
      <div><div class="ct">Android</div>
        <div class="cd">APK-файл для прямого встановлення. Android 6.0+.</div>
      </div>
      <div class="cn"><span>⚠</span> Увімкни «Встановлення з невідомих джерел» перед встановленням.</div>
      <a id="dl-android" class="btn-dl loading" href="#" target="_blank">
        <span class="spinner" id="sp-android"></span><span id="lbl-android">Завантаження...</span>
      </a>
      <div class="fsz" id="sz-android"></div>
    </div>

    <div class="card">
      <div class="ci mac">
        <svg viewBox="0 0 24 24" fill="none">
          <path d="M18.71 19.5C17.88 20.74 17 21.95 15.66 21.97C14.32 22 13.89 21.18 12.37 21.18C10.84 21.18 10.37 21.95 9.1 22C7.78 22.05 6.8 20.68 5.96 19.47C4.25 17 2.94 12.45 4.7 9.39C5.57 7.87 7.13 6.91 8.82 6.88C10.1 6.86 11.32 7.75 12.11 7.75C12.89 7.75 14.37 6.68 15.92 6.84C16.57 6.87 18.39 7.1 19.56 8.82C19.47 8.88 17.39 10.1 17.41 12.63C17.44 15.65 20.06 16.66 20.09 16.67C20.06 16.74 19.67 18.11 18.71 19.5ZM13 3.5C13.73 2.67 14.94 2.04 15.94 2C16.07 3.17 15.6 4.35 14.9 5.19C14.21 6.04 13.07 6.7 11.95 6.61C11.8 5.46 12.36 4.26 13 3.5Z" fill="#94A3B8"/>
        </svg>
      </div>
      <div><div class="ct">macOS</div>
        <div class="cd">ZIP із <code style="color:var(--text-dim);font-size:12px">Sekta.app</code>. Розпакуй та перемісти у «Програми». macOS 12+.</div>
      </div>
      <div class="cn"><span>⚠</span> Якщо macOS блокує — клікни правою кнопкою → «Відкрити».</div>
      <a id="dl-macos" class="btn-dl loading" href="#" target="_blank">
        <span class="spinner" id="sp-macos"></span><span id="lbl-macos">Завантаження...</span>
      </a>
      <div class="fsz" id="sz-macos"></div>
    </div>
  </div>

  <div class="divider"></div>
  <footer>
    <span>Sekta · Внутрішній реліз</span>
    <a href="https://github.com/EugeneSok/sekta-app/releases" target="_blank" rel="noopener">Усі версії на GitHub →</a>
  </footer>
</div>

<script>
${TOPO_JS}
(function(){
  const REPO='EugeneSok/sekta-app';
  const fmt=b=>!b?'':(b<1048576?(b/1024).toFixed(0)+' KB':(b/1048576).toFixed(1)+' MB');
  function ok(id,url,name,size){
    const btn=document.getElementById('dl-'+id),lbl=document.getElementById('lbl-'+id);
    const sp=document.getElementById('sp-'+id),sz=document.getElementById('sz-'+id);
    btn.href=url;btn.classList.remove('loading');lbl.textContent=name;
    if(sp)sp.remove();if(size)sz.textContent=fmt(size);
  }
  function err(id){
    const btn=document.getElementById('dl-'+id),sp=document.getElementById('sp-'+id),lbl=document.getElementById('lbl-'+id);
    if(sp)sp.remove();btn.classList.remove('loading');lbl.textContent='Відкрити реліз';
    btn.href='https://github.com/'+REPO+'/releases/latest';
  }
  fetch('https://api.github.com/repos/'+REPO+'/releases/latest')
    .then(r=>{if(!r.ok)throw r.status;return r.json();})
    .then(rel=>{
      document.getElementById('ver').textContent=rel.tag_name||'—';
      const a=rel.assets||[];
      const w=a.find(x=>x.name.includes('windows')),d=a.find(x=>x.name.includes('android')),m=a.find(x=>x.name.includes('macos'));
      if(w)ok('windows',w.browser_download_url,w.name,w.size);else err('windows');
      if(d)ok('android',d.browser_download_url,d.name,d.size);else err('android');
      if(m)ok('macos',m.browser_download_url,m.name,m.size);else err('macos');
    }).catch(()=>{document.getElementById('ver').textContent='Помилка';['windows','android','macos'].forEach(err);});
})();
</script>
</body></html>`;
}

function deniedPage(login) {
  return `<!DOCTYPE html><html lang="uk"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Доступ заборонено</title><link rel="icon" type="image/png" href="/logo.png">
<style>
${BASE_CSS}
.wrap{position:relative;z-index:1;display:flex;flex-direction:column;align-items:center;
  justify-content:center;min-height:100vh;padding:24px;text-align:center;}
.icon{font-size:48px;margin-bottom:16px;}
h1{font-size:22px;font-weight:700;color:var(--text);margin-bottom:8px;}
p{font-size:14px;color:var(--text-muted);max-width:360px;line-height:1.6;margin-bottom:24px;}
code{color:var(--text-dim);background:var(--bg2);padding:2px 6px;border-radius:4px;font-size:13px;}
a{display:inline-flex;align-items:center;gap:6px;color:var(--text-muted);text-decoration:none;
  font-size:14px;border:1px solid var(--border);border-radius:8px;padding:8px 16px;
  transition:border-color .2s,color .2s;}
a:hover{border-color:var(--text-muted);color:var(--text-dim);}
</style></head><body>
<canvas id="topo"></canvas>
<div class="wrap">
  <div class="icon">🔒</div>
  <h1>Доступ заборонено</h1>
  <p>Акаунт <code>@${login}</code> не має доступу до цієї сторінки.<br>
  Зверніться до адміністратора.</p>
  <a href="/auth/logout">← Вийти</a>
</div>
<script>${TOPO_JS}</script>
</body></html>`;
}

function errorPage(msg) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Помилка</title>
<style>body{background:#0F1419;color:#E2E8F0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;}</style>
</head><body><div style="text-align:center"><h2>Помилка авторизації</h2><p style="color:#64748B">${msg}</p>
<a href="/" style="color:#2563EB">← Назад</a></div></body></html>`;
}
