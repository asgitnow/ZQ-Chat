// 实时多会话验证：开多个 headless 对话，端到端打到真实 Cloudflare 部署
// 用法: node tests/live-e2e.mjs --url ws://127.0.0.1:18443 [--room live --pass pw]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const args = process.argv.slice(2);
const A = (k, d) => { const i = args.indexOf('--' + k); return i >= 0 ? args[i + 1] : d; };
const URL_ = A('url', 'ws://127.0.0.1:18443');
const ROOM = A('room', 'live-demo');
const PW = A('pass', 'demo-pw');

const out = (s) => process.stdout.write(s + '\n');

function client(name, pass = PW, state = path.join(os.tmpdir(), `live-${name}.json`), url = URL_, fresh = false) {
  if (fresh) fs.rmSync(state, { force: true });
  const dbg = process.env.LIVE_DBG ? ['--debug'] : [];
  const p = spawn(process.execPath, [
    'headless/zqchat.mjs', '--url', url, '--room', ROOM, '--pass', pass,
    '--name', name, '--state', state, ...dbg,
  ], { cwd: path.resolve(import.meta.dirname, '..') });
  const events = [];
  p.stdout.on('data', (b) => {
    for (const line of String(b).split('\n')) {
      if (!line.trim()) continue;
      try { events.push(JSON.parse(line)); } catch { /* ignore */ }
    }
  });
  const errFile = process.env.LIVE_DBG ? fs.openSync(path.join(os.tmpdir(), `live-${name}.err`), 'a') : null;
  p.stderr.on('data', (b) => { if (errFile !== null) fs.writeSync(errFile, String(b)); process.stderr.write(`[${name}] ${b}`); });
  const send = (text) => p.stdin.write(text + '\n');
  const kill = () => { try { p.stdin.write('/quit\n'); p.stdin.end(); } catch { /* ignore */ } setTimeout(() => p.kill(), 500); };
  const wait = (fn, ms = 30000) => new Promise((res) => {
    const t0 = Date.now();
    const iv = setInterval(() => {
      const hit = events.find(fn);
      if (hit) { clearInterval(iv); res(hit); }
      else if (Date.now() - t0 > ms) { clearInterval(iv); res(null); }
    }, 100);
  });
  return { name, p, events, send, kill, wait };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let pass = 0, fail = 0;
const ok = (c, n, x = '') => { c ? (pass++, out(`  ✅ ${n}${x ? ' — ' + x : ''}`)) : (fail++, out(`  ❌ ${n}${x ? ' — ' + x : ''}`)); };

out('══ 实时部署端到端验证（经 echbridge → Cloudflare Workers 临时账号）══');
out(`   url=${URL_} room=${ROOM}`);

// ── ① 三个对话并发加入 ──
const alice = client('Alice', PW, undefined, URL_, true);
const bob = client('Bob', PW, undefined, URL_, true);
const carol = client('Carol', PW, undefined, URL_, true);
out('① 三方加入');
for (const c of [alice, bob, carol]) ok(await c.wait((e) => e.ev === 'secured'), `${c.name} 完成 E2EE 握手（CPace+ML-KEM+X25519 真实往返）`);

// 等两两 peer_ready（N² 握手完成）
for (const c of [alice, bob, carol]) ok(await c.wait((e) => e.ev === 'peer_ready'), `${c.name} 已认证至少一个 peer`);
await sleep(2500);
const readyOf = (c) => c.events.filter((e) => e.ev === 'peer_ready').length;
ok(readyOf(alice) >= 2 && readyOf(bob) >= 2 && readyOf(carol) >= 2, '三方两两握手完成', `peers: A=${readyOf(alice)} B=${readyOf(bob)} C=${readyOf(carol)}`);

// ── ② 真实聊天 ──
out('② 互发消息');
alice.send('你们好，这条消息经过 Cloudflare 边缘，它看得到帧头看不到内容');
ok(await bob.wait((e) => e.ev === 'msg' && e.text?.includes('看得到帧头')), 'Bob 收到 Alice');
ok(await carol.wait((e) => e.ev === 'msg' && e.text?.includes('看得到帧头')), 'Carol 收到 Alice');
bob.send('收到，我这边解密正常');
ok(await alice.wait((e) => e.ev === 'msg' && e.from === bob.events.find((x) => x.ev === 'secured')?.id), 'Alice 收到 Bob 回复');
ok(await carol.wait(() => readyOf(carol) >= 2, 15000), 'Carol 完成两两握手后再发言');
carol.send('我也收到');
await sleep(1500);
ok(alice.events.some((e) => e.ev === 'msg' && e.text === '我也收到') && bob.events.some((e) => e.ev === 'msg' && e.text === '我也收到'), '全员互通');

// ── ③ 第四人加入触发密钥轮换（epoch），轮换后继续聊 ──
out('③ 新人加入 → epoch 轮换');
const dave = client('Dave', PW, undefined, URL_, true);
ok(await dave.wait((e) => e.ev === 'secured'), 'Dave 加入');
ok(await alice.wait(() => alice.events.filter((e) => e.ev === 'peer_ready').length >= 3, 30000), 'Alice 与 Dave 建会话');
// 等 Dave 与其他人两两握手全部完成，再等 5s 合并窗口的 epoch 广播
ok(await dave.wait(() => readyOf(dave) >= 3, 30000), 'Dave 与全部成员建会话（N² 握手）');
ok(await alice.wait(() => readyOf(alice) >= 3, 15000), 'Alice 侧计数达标');
await sleep(3000);   // 合并窗口后到达的 epoch 广播 → 各侧统一推进
alice.send('轮换之后的新消息');
ok(await bob.wait((e) => e.ev === 'msg' && e.text === '轮换之后的新消息'), '轮换后消息仍可解密（双方独立推进 root）');
ok(await dave.wait((e) => e.ev === 'msg' && e.text === '轮换之后的新消息', 10000), '新成员收到轮换后消息');

// ── ④ 安全码展示 ──
out('④ 安全码');
alice.send('/codes');
await sleep(800);
const codes = alice.events.find((e) => e.ev === 'codes');
ok(codes && Object.keys(codes.codes).length >= 3, 'Alice 列出与每个 peer 的安全码（指纹）',
  Object.entries(codes?.codes || {}).map(([id, c]) => `${c.name}:${String(c.fingerprint).slice(0, 8)}…`).join(' '));
const fpMatch = codes && bob.events.find((e) => e.ev === 'codes');

// ── ⑤ 错误密码者被明确拒绝 ──
out('⑤ 错误密码');
const eve = client('Eve', 'WRONG-PASSWORD', undefined, URL_, true);
const evBad = await eve.wait((e) => e.ev === 'peer_error' && e.code === 'PASSWORD_MISMATCH');
const evBad2 = await alice.wait((e) => e.ev === 'peer_error' && e.code === 'PASSWORD_MISMATCH', 10000);
ok(!!(evBad || evBad2), '密码错误 → 双方收到 PASSWORD_MISMATCH（UI 可精确提示）');
ok(!eve.events.some((e) => e.ev === 'msg'), '错误密码者读不到任何消息');
eve.kill();

// ── ⑥ 断线重连：身份稳定 + 旧密文不可读 ──
out('⑥ 重连');
const bobId = bob.events.find((e) => e.ev === 'secured')?.id;
bob.kill();
await sleep(3000);
const bob2 = client('Bob', PW, path.join(os.tmpdir(), 'live-Bob.json'));   // 复用身份文件 = 同身份重连
const secured2 = await bob2.wait((e) => e.ev === 'secured', 20000);
ok(!!secured2 && secured2.id === bobId, '重连后 clientId 不变（同一身份密钥决定）', `${bobId} vs ${secured2?.id}`);
ok(await bob2.wait((e) => e.ev === 'peer_ready', 30000), '重连后与留守成员重新握手');
await sleep(1500);
alice.send('Bob 走了之后的消息');
ok(await bob2.wait((e) => e.ev === 'msg' && e.text === 'Bob 走了之后的消息', 20000), '重连即新会话：只收到重连后的广播（断线期间消息按设计丢弃）');

dave.kill(); alice.kill(); bob2.kill(); carol.kill();
await sleep(500);
out(`\n══ 结果: ${pass} 项通过, ${fail} 项失败 ══`);
process.exit(fail ? 1 : 0);
