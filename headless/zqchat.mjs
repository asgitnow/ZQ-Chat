#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════
//  zqchat —— headless 聊天通道（CLI）
//
//  与浏览器客户端复用同一份 NodeCrypt/zqcrypto 实现，用于：
//   · 无浏览器环境下的端到端验证（agent 可开多个实例互聊）
//   · 脚本化 E2E（--e2e 断言模式）
//   · 人工 headless 聊天（stdin 交互）
//
//  用法：
//   node headless/zqchat.mjs --url ws://host --room demo --pass pw --name alice
//        [--state ./alice.json] [--send "hi"] [--expect "hello"]
//        [--watch 15] [--codes] [--e2e] [--debug]
//
//  URL 可以是 ws://127.0.0.1:<port>/（经本地 ECH 桥）或 wss://直接可达的环境。
// ═══════════════════════════════════════════════════════════════════════
import fs from 'node:fs';
import path from 'node:path';
import NodeCrypt from '../client/js/NodeCrypt.js';

const args = process.argv.slice(2);
const opts0name = (() => { const i = args.indexOf('--name'); return i >= 0 ? args[i + 1] : 'guest'; })();
function arg(name, def = undefined) {
  const i = args.indexOf('--' + name);
  if (i >= 0) return args[i + 1];
  const eq = args.find((a) => a.startsWith('--' + name + '='));
  return eq ? eq.split('=').slice(1).join('=') : def;
}
const flag = (name) => args.includes('--' + name);

const opts = {
  url: arg('url', 'ws://127.0.0.1:8799'),
  room: arg('room', 'demo'),
  pass: arg('pass', ''),
  name: arg('name', 'guest' + Math.floor(Math.random() * 1e4)),
  state: arg('state', `./.zqchat-${opts0name}.json`),
  send: arg('send'),
  expect: arg('expect'),
  watch: Number(arg('watch', 0)),
  mode: arg('mode', 'interactive'),          // interactive | one-shot
  debug: flag('debug'),
};

// 文件型 localStorage 替身（身份持久化）
class FileStorage {
  constructor(file) {
    this.file = path.resolve(file);
    this.map = {};
    try { fs.mkdirSync(path.dirname(this.file), { recursive: true }); } catch { /* ignore */ }
    try { this.map = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch { /* new */ }
  }
  getItem(k) { return this.map[k] ?? null; }
  setItem(k, v) {
    this.map[k] = v;
    try { fs.writeFileSync(this.file, JSON.stringify(this.map)); }
    catch (e) {
      // 身份写不下去会静默退化成"每次重连都是新人"，必须显式报出
      process.stderr.write(`[zq] 身份持久化失败（${e.code}）: ${this.file}\n`);
      process.exit(3);
    }
  }
}

const out = (obj) => process.stdout.write(JSON.stringify(obj) + '\n');
if (opts.debug) { console.log = (...a) => console.error('[nc]', ...a); }   // 协议日志归位 stderr
const log = (...a) => { if (opts.debug) console.error('[zq]', ...a); };

const storage = new FileStorage(opts.state);
const callbacks = {
  onServerClosed: () => { out({ ev: 'closed' }); },
  onServerSecured: () => { out({ ev: 'secured', id: chat.identity.id }); },
  onClientSecured: (u) => { out({ ev: 'peer_ready', id: u.clientId, name: u.username }); },
  onClientList: (list) => { peerList = list; },
  onClientMessage: (m) => {
    if (m.type === 'text') out({ ev: 'msg', from: m.clientId, name: m.username, text: m.data });
    else out({ ev: 'msg_other', from: m.clientId, name: m.username, type: m.type });
  },
  onClientLeft: (u) => { out({ ev: 'peer_left', id: u.clientId }); },
  onPeerError: (e) => { out({ ev: 'peer_error', ...e }); },
  onRoomError: (e) => { out({ ev: 'room_error', ...e }); },
};

let peerList = [];
const chat = new NodeCrypt({
  wsAddress: opts.url,
  debug: opts.debug,
  storage,
}, callbacks);
chat.setCredentials(opts.name, opts.room, opts.pass);
chat.connect();

function sendText(text) {
  const ok = chat.sendChannelMessage('text', text);
  out({ ev: 'sent', ok, len: text.length });
  return ok;
}

// —— 一次性模式：--send 后等待 --expect 或超时 ——
if (opts.mode === 'one-shot' || opts.send) {
  const deadline = Date.now() + (opts.watch ? opts.watch * 1000 : 15000);
  const waitSecure = () => new Promise((res) => {
    if (chat.serverShared) return res();
    const iv = setInterval(() => { if (chat.serverShared) { clearInterval(iv); res(); } }, 100);
    setTimeout(() => { clearInterval(iv); res(); }, deadline - Date.now());
  });
  (async () => {
    await waitSecure();
    if (opts.send) {
      // 等至少一个 peer 就绪再发（有对端场景）；纯加入验证允许无对端
      const waitPeer = new Promise((res) => {
        const t0 = Date.now();
        const iv = setInterval(() => {
          if (peerList.length > 0 || Date.now() > t0 + 6000) { clearInterval(iv); res(); }
        }, 100);
      });
      await waitPeer;
      sendText(opts.send);
    }
    if (opts.expect) {
      // 等期待内容出现在收到的消息里
      const got = await new Promise((res) => {
        const t0 = Date.now();
        const orig = callbacks.onClientMessage;
        chat.callbacks.onClientMessage = (m) => { orig(m); if (m.type === 'text' && String(m.data).includes(opts.expect)) { clearInterval(iv); res(true); } };
        const iv = setInterval(() => { if (Date.now() > t0 + (deadline - t0)) { clearInterval(iv); res(false); } }, 200);
      });
      out({ ev: 'expect', found: got, needle: opts.expect });
      chat.destruct();
      process.exit(got ? 0 : 2);
    }
    if (opts.watch) { setTimeout(() => { chat.destruct(); process.exit(0); }, opts.watch * 1000); }
    else { chat.destruct(); process.exit(0); }
  })();
} else {
  // —— 交互模式：stdin 逐行发送；/quit /peers /codes /id ——
  out({ ev: 'start', name: opts.name, url: opts.url, room: opts.room });
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (d) => {
    buf += d;
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).replace(/\r$/, '');
      buf = buf.slice(nl + 1);
      if (line === '/quit') { chat.destruct(); process.exit(0); }
      else if (line === '/peers') out({ ev: 'peers', list: peerList });
      else if (line === '/id') out({ ev: 'id', id: chat.identity.id });
      else if (line === '/codes') {
        const codes = {};
        for (const pid in chat.channel) {
          const s = chat.channel[pid];
          if (s.shared) codes[pid] = { name: s.username, fingerprint: s.shared.fingerprint, auth: s.shared.authMode };
        }
        out({ ev: 'codes', codes });
      }
      else if (line.trim()) sendText(line);
    }
  });
  process.stdin.on('end', () => { chat.destruct(); process.exit(0); });
}
