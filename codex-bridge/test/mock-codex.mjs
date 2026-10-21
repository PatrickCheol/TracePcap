import { createInterface } from 'node:readline';

const send = value => process.stdout.write(`${JSON.stringify(value)}\n`);
let authenticated = process.env.MOCK_AUTH === 'true';
let threads = 0;
const mode = process.env.MOCK_MODE;
const notify = (method, params) => send({ method, params });
const lines = createInterface({ input: process.stdin });
lines.on('line', line => {
  const message = JSON.parse(line);
  if (!message.method) {
    notify('test/serverResponse', message);
    return;
  }
  const { id, method, params } = message;
  notify('test/request', { method, params });
  let result = {};
  if (method === 'initialize') result = { userAgent: 'mock-codex' };
  if (method === 'initialized') return;
  if (method === 'account/read') result = { account: authenticated ? { type: 'chatgpt', email: 'private@example.test', planType: 'plus', secret: 'test-secret-DO-NOT-LEAK' } : null, requiresOpenaiAuth: true };
  if (method === 'account/login/start') {
    authenticated = mode !== 'login-fails';
    // Deliberately notify before sending the RPC result.
    notify('account/login/completed', { loginId: 'login-1', success: authenticated, error: authenticated ? null : 'test-secret-DO-NOT-LEAK' });
    result = { type: 'chatgptDeviceCode', loginId: 'login-1', verificationUrl: 'https://auth.openai.com/codex/device', userCode: 'TEST-1234' };
  }
  if (method === 'account/logout') authenticated = false;
  if (method === 'thread/start') {
    if (mode === 'model-failure') {
      send({ id, error: { code: -32603, message: 'model access denied: test-secret-DO-NOT-LEAK' } });
      return;
    }
    result = { thread: { id: `thread-${++threads}` } };
  }
  if (method === 'turn/start') {
    const threadId = params.threadId, turnId = `turn-${threads}`;
    result = { turn: { id: turnId, status: 'inProgress' } };
    if (mode === 'exit') return process.exit(1);
    notify('turn/started', { threadId, turn: result.turn });
    if (mode === 'server-request') {
      send({ id: 'approval-1', method: 'item/commandExecution/requestApproval', params: { threadId, turnId, command: 'read-secret' } });
    } else if (mode === 'tool') {
      notify('item/started', { threadId, turnId, item: { id: 'tool', type: 'commandExecution' } });
    } else if (mode === 'failure') {
      notify('turn/completed', { threadId, turn: { id: turnId, status: 'failed', error: { message: 'test-secret-DO-NOT-LEAK' } } });
    } else if (mode === 'context-limit') {
      notify('error', { threadId, turnId, willRetry: false, error: { codexErrorInfo: 'contextWindowExceeded', message: 'test-secret-DO-NOT-LEAK' } });
    } else if (mode === 'rate-limit') {
      notify('turn/completed', { threadId, turn: { id: turnId, status: 'failed', error: { codexErrorInfo: 'rateLimitExceeded', message: 'test-secret-DO-NOT-LEAK' } } });
    } else if (mode !== 'timeout') {
      notify('item/completed', { threadId, turnId, item: { id: 'commentary', type: 'agentMessage', phase: 'commentary', text: 'Do not return commentary' } });
      notify('item/completed', { threadId, turnId, item: { id: 'answer', type: 'agentMessage', phase: 'final_answer', text: '{"summary":"Packet evidence analyzed"}' } });
      notify('thread/tokenUsage/updated', { threadId, turnId, tokenUsage: { last: { inputTokens: 10, outputTokens: 20, totalTokens: 30 } } });
      notify('turn/completed', { threadId, turn: { id: turnId, status: 'completed' } });
    }
  }
  send({ id, result });
});
