// ═══════════════════════════════════════════════════════════════════════
//  relay-harness —— 在 Node 里运行真实 worker/index.js（盲中继）代码
//
//  提供 WebSocketPair / Durable Object namespace / Request 的最小替身，
//  其余全部走真实 worker 源码路径（含 crypto.subtle Ed25519 验签）。
//
//  onopen 触发路径唯一：makeWsFactory 绑定完成后向 NodeCrypt 投递一次；
//  直连（raw protocol 测试）由调用方自行 client.fireOpen()。
// ═══════════════════════════════════════════════════════════════════════

export class WSLink {
  constructor(name) {
    this.name = name;
    this.readyState = 0;
    this.listeners = { message: [], close: [], error: [] };
    this.peer = null;
    this._handlers = {};
    this.sentLog = [];
  }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn); }
  accept() { this.readyState = 1; }
  send(str) {
    if (this.readyState !== 1) return;
    this.sentLog.push(str);
    const p = this.peer;
    if (!p || p.readyState === 3) return;
    setTimeout(() => {
      const ev = { data: str };
      for (const fn of p.listeners.message) { try { fn(ev); } catch (e) { console.error('relay msg handler err', e && e.message); } }
      if (p._handlers.onmessage) { try { p._handlers.onmessage(ev); } catch (e) { console.error('client onmessage err', e && e.message); } }
    }, 0);
  }
  close(code = 1000, reason = '') {
    if (this.readyState === 3) return;
    this.readyState = 3;
    setTimeout(() => this._fireClose(code, reason), 0);
  }
  _fireClose(code, reason) {
    for (const fn of this.listeners.close) { try { fn({ code, reason }); } catch { /* ignore */ } }
    if (this._handlers.onclose) { try { this._handlers.onclose({ code, reason }); } catch { /* ignore */ } }
    const p = this.peer;
    if (p && p.readyState !== 3) {
      p.readyState = 3;
      setTimeout(() => {
        for (const fn of p.listeners.close) { try { fn({ code, reason }); } catch { /* ignore */ } }
        if (p._handlers.onclose) { try { p._handlers.onclose({ code, reason }); } catch { /* ignore */ } }
      }, 0);
    }
  }
  fireOpen() {
    this.readyState = 1;
    setTimeout(() => {
      if (this._handlers.onopen) { try { this._handlers.onopen({}); } catch (e) { console.error('onopen err', e && e.message); } }
    }, 0);
  }
}
for (const key of ['onopen', 'onmessage', 'onclose', 'onerror']) {
  Object.defineProperty(WSLink.prototype, key, {
    set(fn) { this._handlers[key] = fn; },
    get() { return this._handlers[key]; },
    configurable: true,
  });
}

export function createRelay() {
  // Node 的 undici Response 不允许 status 101；测试环境垫片（不影响浏览器/Workers）
  const RealResponse = globalThis.Response;
  globalThis.Response = class ExtResponse extends RealResponse {
    constructor(body, init) {
      if (init && (init.status === 101 || init.status === 426)) {
        const o = Object.create(ExtResponse.prototype);
        Object.defineProperty(o, 'status', { value: init.status });
        if (init.webSocket) Object.defineProperty(o, 'webSocket', { value: init.webSocket });
        return o;
      }
      return new RealResponse(body, init);
    }
  };

  const pairs = [];
  globalThis.WebSocketPair = class {
    constructor() {
      const client = new WSLink('client');
      const server = new WSLink('server');
      client.peer = server; server.peer = client;
      this.clientSide = client;   // Object.values 顺序：先 client 后 server（与 worker 解构语义一致）
      this.serverSide = server;
      pairs.push({ client, server });
    }
  };

  let ChatRoomCls = null;
  const workerP = import('../worker/index.js').then((m) => { ChatRoomCls = m.ChatRoom; return m.default; });

  const instances = new Map();
  const seenDoIds = new Set();

  const env = {
    CHAT_ROOM: {
      idFromName: (name) => `DO::${name}`,
      get: (id) => {
        seenDoIds.add(id);
        if (!instances.has(id)) {
          const state = { id, storage: { async get() { return undefined; }, async put() { }, async delete() { } } };
          instances.set(id, { room: new ChatRoomCls(state, env) });
        }
        return { fetch: (request) => instances.get(id).room.fetch(request) };
      },
    },
    ASSETS: { fetch: async () => new RealResponse('assets') },
  };

  // 串行化，保证 pairs[last] 与本次 connect 一一对应
  let chain = Promise.resolve();

  async function _connect(roomHash, ip = '203.0.113.1') {
    const worker = await workerP;
    // undici Request 会静默丢弃受限头（Upgrade），用轻量替身保证真实路由分支被执行
    const hdrs = { upgrade: 'websocket', 'cf-connecting-ip': ip };
    const request = {
      url: `https://relay.test/chat?r=${roomHash}`,
      headers: { get: (k) => hdrs[String(k).toLowerCase()] ?? null },
    };
    const resp = await worker.fetch(request, env, { waitUntil() { } });
    if (resp.status !== 101) return { error: `status ${resp.status}`, client: null, server: null };
    const pair = pairs[pairs.length - 1];
    if (!pair) return { error: 'no pair', client: null, server: null };
    return pair;
  }

  function connect(roomHash, ip) {
    const run = chain.then(() => _connect(roomHash, ip));
    chain = run.then(() => { }, () => { });
    return run;
  }

  return { pairs, env, seenDoIds, connect, ready: workerP };
}

/** 给 NodeCrypt 用的 wsFactory：异步建链 → 接管处理器 → 投递唯一一次 onopen */
export function makeWsFactory(relay, roomHash, opts = {}) {
  return function (url) {
    const placeholder = new WSLink('placeholder');
    placeholder.readyState = 0;
    placeholder.send = () => false;   // 真实链就绪前丢弃（NodeCrypt 只在 onopen 后发送）
    relay.connect(roomHash, opts.ip)
      .catch((e) => { console.error('!! relay.connect failed:', e && (e.stack || e.message)); return null; })
      .then((pair) => {
        const client = pair && pair.client;
        if (!client) {
          placeholder.readyState = 3;
          if (placeholder._handlers.onclose) placeholder._handlers.onclose({ code: 1006 });
          return;
        }
        client._handlers = placeholder._handlers;   // NodeCrypt 注册过的处理器直接接管
        client.readyState = 1;                      // 真实链对客户端可见为 OPEN
        placeholder.readyState = 1;
        placeholder.send = (s) => client.send(s);
        placeholder.close = (c, r) => client.close(c, r);
        if (client._handlers.onopen && !client._openDelivered) {
          client._openDelivered = true;
          setTimeout(() => { try { client._handlers.onopen({}); } catch (e) { console.error('onopen err', e && e.message); } }, 0);
        }
      });
    return placeholder;
  };
}
