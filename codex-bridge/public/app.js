const element = id => document.getElementById(id);
let busy = false;

async function request(path, method = 'GET') {
  const response = await fetch(path, { method, cache: 'no-store', ...(method === 'POST' ? { headers: { 'Content-Type': 'application/json' }, body: '{}' } : {}) });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error?.message || '요청을 처리하지 못했습니다.');
  return body;
}

async function status() {
  try {
    const result = await request('/auth/status');
    element('status').textContent = result.authenticated ? 'ChatGPT 연결 완료 · TracePcap에서 AI 분석을 실행할 수 있습니다.' : result.loginPending ? 'OpenAI 로그인 완료를 기다리는 중…' : 'ChatGPT에 연결되어 있지 않습니다.';
    element('login').disabled = busy || result.authenticated;
    element('login').hidden = result.authenticated;
    element('logout').hidden = !result.authenticated && !result.loginPending;
    if (result.authenticated || !result.loginPending) element('device').hidden = true;
    if (result.error) element('error').textContent = result.error;
  } catch {
    element('status').textContent = '연결 상태를 확인할 수 없습니다. Docker의 codex-bridge 서비스를 확인하세요.';
    element('login').disabled = false;
  }
}

element('login').addEventListener('click', async () => {
  busy = true; element('login').disabled = true; element('error').textContent = '';
  try {
    const result = await request('/auth/login', 'POST');
    element('verification').href = result.verificationUrl;
    element('code').textContent = result.userCode;
    element('device').hidden = false;
  } catch (error) { element('error').textContent = error.message; }
  finally { busy = false; await status(); }
});

element('logout').addEventListener('click', async () => {
  element('logout').disabled = true; element('error').textContent = '';
  try { await request('/auth/logout', 'POST'); element('device').hidden = true; }
  catch (error) { element('error').textContent = error.message; }
  finally { element('logout').disabled = false; await status(); }
});

status();
setInterval(status, 3000);
