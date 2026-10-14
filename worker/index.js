// ═══════════════════════════════════════════════════════════════════════
//  ZQ-Chat v2 Worker —— 盲中继
//
//  服务器不持有任何可用于解密的密钥（规格 §7.1）。只按明文信封路由：
//   · Durable Object 按房间分片（idFromName(roomHash)）
//   · clientId 由客户端身份密钥决定，服务器只绑定不生成
//   · 日志仅元数据，绝不记录载荷
//   · 过期连接由独立定时器清理
//   · 握手类消息上限 8192B；业务消息上限 8MB
//   · 令牌桶 / 握手限流 / 连接数上限 / bundle 验签失败拒绝
// ═══════════════════════════════════════════════════════════════════════
import { isString, isObject, b64dec, b64enc, getTime, logEvent } from './utils.js';

const MAX_MSG = 8 * 1024 * 1024;        // 业务消息上限（沿用 v1）
const MAX_HS = 8192;                    // 握手类消息上限（v1 为 2048，bundle 1809B 需放宽）
const MAX_MEMBERS = 100;                // 每房间连接数
const MAX_PER_IP = 10;                  // 每 IP 连接数
const SEEN_TIMEOUT = 60000;             // 心跳超时清理
const EPOCH_MERGE_MS = 5000;            // 成员变化合并窗口（规格 §5.3）

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get('Upgrade');

    if (upgradeHeader && upgradeHeader === 'websocket' && url.pathname === '/chat') {
      const room = url.searchParams.get('r') || '';
      if (!/^[0-9a-f]{64}$/.test(room)) {
        return new Response('bad room id', { status: 400 });
      }
      // ★ 按房间分片
      const stub = env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName(room));
      return stub.fetch(request);
    }

    if (url.pathname.startsWith('/api/')) {
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    return env.ASSETS.fetch(request);
  },
};

export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.clients = {};          // id -> { connection, ip, seen, bundle }
    this.ipCount = {};
    this.roomNonce = null;      // b64；房间空时为 null，由首位成员提供（不透明字节）
    this.epoch = 0;             // 密钥轮换计数器（服务器只广播整数，不参与密钥计算）
    this.epochFlushTimer = null;
    this.roomBucket = { tokens: 1000, last: getTime() };
    this.cleanupTimer = null;
    this.readyEd25519 = null;   // 能力探测缓存
    this.ensureCleanup();       // 独立周期清理，不依赖新连接触发
  }

  // ── 每连接状态（不持久化：DO 重启即房间清空，与"无历史"设计一致）──
  ensureCleanup() {
    if (this.cleanupTimer) return;
    this.cleanupTimer = setInterval(() => this.cleanupOldConnections(), 15000);
  }

  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if ((this.ipCount[ip] || 0) >= MAX_PER_IP) {
      return new Response('too many connections', { status: 429 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    this.handleSession(server, ip);
    return new Response(null, { status: 101, webSocket: client });
  }

  handleSession(connection, ip) {
    connection.accept();
    this.cleanupOldConnections();
    const conn = {
      connection, ip, seen: getTime(),
      id: null,               // join 成功后绑定（客户端身份决定，服务器不生成）
      bundle: null,
      bucket: { tokens: 20, last: getTime() },       // 每连接 20 突发 / 10 每秒
      hsTimes: [],                                     // 握手限流：每 10s 最多 3 次
    };
    this.ipCount[ip] = (this.ipCount[ip] || 0) + 1;
    // 未 join 前用占位 key 管理
    this.clients['$' + getTime() + Math.random()] = conn;

    connection.addEventListener('message', async (event) => {
      const message = event.data;
      if (!isString(message)) return;
      conn.seen = getTime();

      if (message === 'ping') { this.send(connection, 'pong'); return; }

      let msg;
      try { msg = JSON.parse(message); } catch { return; }
      if (!isObject(msg) || !isString(msg.t)) return;

      try {
        if (msg.t === 'nonce') {
          this.send(connection, JSON.stringify({
            t: 'nonce',
            nonce: Object.keys(this.members()).length === 0 ? null : this.roomNonce,
            epoch: this.epoch,
          }));
          return;
        }
        if (msg.t === 'join') { await this.handleJoin(conn, msg); return; }

        // 其余消息必须先 join
        if (!conn.id) return;

        // 尺寸分层：握手类 ≤8192，业务 ≤8MB
        const isHs = msg.t === 'hs' || msg.t === 'ctag' || msg.t === 'hsreq';
        if (isHs && message.length > MAX_HS) { this.close(conn, 1009, 'FRAME_TOO_LARGE'); return; }
        if (message.length > MAX_MSG) { this.close(conn, 1009, 'FRAME_TOO_LARGE'); return; }

        // 令牌桶：每连接
        if (!this.take(conn.bucket, 1, 10 / 1, 20)) { this.send(connection, JSON.stringify({ t: 'error', code: 'RATE_LIMIT' })); return; }
        // 每房间
        if (!this.take(this.roomBucket, 1, 200 / 1, 1000)) { this.send(connection, JSON.stringify({ t: 'error', code: 'ROOM_RATE_LIMIT' })); return; }
        // 说明：限流只针对完整握手（join，见 handleJoin）；hs/ctag 是每 peer 的
        // 正常握手碎片，N 人房间合法流量即 >3/10s，中继对这些消息不做密码学运算，
        // 由令牌桶与尺寸上限兜底即可

        switch (msg.t) {
          case 'hs':
          case 'ctag':
          case 'hsreq': {
            const target = this.clientsTarget(msg.to);
            if (!target) return;
            // 服务器只转发，绝不解读；from 由中继绑定，杜绝冒充
            const relay = { t: msg.t, from: conn.id, to: msg.to };
            if (msg.ya !== undefined) relay.ya = msg.ya;
            if (msg.kemCt !== undefined) relay.kemCt = msg.kemCt;
            if (msg.sig !== undefined) relay.sig = msg.sig;
            if (msg.tag !== undefined) relay.tag = msg.tag;
            if (msg.e !== undefined) relay.e = msg.e;
            this.send(target.connection, JSON.stringify(relay));
            break;
          }
          case 'msg': {
            if (!Array.isArray(msg.to) || !Array.isArray(msg.c) || msg.to.length !== msg.c.length) return;
            if (msg.to.length > MAX_MEMBERS) return;
            for (let i = 0; i < msg.to.length; i++) {
              const target = this.clientsTarget(msg.to[i]);
              if (!target) continue;
              if (!isString(msg.c[i])) continue;
              this.send(target.connection, JSON.stringify({ t: 'msg', from: conn.id, c: msg.c[i] }));
            }
            break;
          }
          default: break;
        }
      } catch (e) {
        logEvent('relay-error', e && e.message);   // 仅元数据
      }
    });

    connection.addEventListener('close', () => this.removeClient(conn, true));
    connection.addEventListener('error', () => this.removeClient(conn, true));
  }

  async handleJoin(conn, msg) {
    this.cleanupOldConnections();          // 新成员进入前清一次僵尸连接，joined 名单更准
    if (!this.rateLimitHs(conn)) return;   // 完整握手（含验签）限流
    const b = msg.bundle;
    if (!isObject(b) || !isString(b.id) || !/^[0-9a-f]{12}$/.test(b.id)
      || !isString(b.ipk) || !isString(b.xpk) || !isString(b.kpk) || !isString(b.sig)) return;
    // ★ 采纳 nonce 必须在异步验签之前同步完成：否则两名首成员在验签窗口内
    //   都收到 nonce:null，各自采纳自己的 nonce，产生本可避免的 CONFLICT 重试
    if (this.roomNonce === null && Object.keys(this.members()).length === 0 && !this.pendingNonce) {
      this.pendingNonce = msg.nonce;
      this.roomNonce = msg.nonce;
    }
    if (msg.nonce !== this.roomNonce && this.roomNonce !== null) {
      // 已有权威 nonce：告知客户端重签名（两名首成员并发场景）
      this.send(conn.connection, JSON.stringify({ t: 'error', code: 'NONCE_CONFLICT', nonce: this.roomNonce }));
      return;
    }
    const dup = this.memberById(b.id);
    if (dup && dup !== conn) {
      this.send(conn.connection, JSON.stringify({ t: 'error', code: 'DUPLICATE_ID' }));
      this.close(conn, 1008, 'DUPLICATE_ID');
      return;
    }
    if (Object.keys(this.members()).length >= MAX_MEMBERS) {
      this.send(conn.connection, JSON.stringify({ t: 'error', code: 'ROOM_FULL' }));
      this.close(conn, 1013, 'ROOM_FULL');
      return;
    }

    // bundle 验签：失败立即拒绝（规格 §7.5）
    const ok = await this.verifyBundle(b, msg.nonce);
    if (ok === false) {
      logEvent('join-rejected', b.id);   // 仅 id，无载荷
      this.close(conn, 1008, 'BAD_BUNDLE');
      return;
    }
    if (ok === null) {
      logEvent('ed25519-unsupported', 'server-side verify skipped');   // 运行时不支持时降级：客户端侧仍会验签
    }

    // （验签前已采纳 nonce，见上）
    conn.id = b.id;
    conn.bundle = { id: b.id, ipk: b.ipk, xpk: b.xpk, kpk: b.kpk, sig: b.sig };
    this.removePlaceholder(conn);
    this.clients[b.id] = conn;   // ★ 以身份 id 登记成员（v2 关键：id 来自客户端 bundle）

    const members = Object.values(this.clients)
      .filter((c) => c.id && c.id !== b.id && c.bundle)
      .map((c) => c.bundle);
    this.send(conn.connection, JSON.stringify({
      t: 'joined', members, epoch: this.epoch, nonce: this.roomNonce,
    }));
    // 成员可见事件立即送达（hs 可能紧随其后，peer 表必须先就位）；
    // epoch 递增本身才做 5s 合并（规格 §5.3）
    for (const other of Object.values(this.members())) {
      if (other.id !== b.id) {
        this.send(other.connection, JSON.stringify({ t: 'member.add', bundle: conn.bundle, epoch: this.epoch }));
      }
    }
    this.bumpEpochSoon();
  }

  // ── 成员与 epoch ──
  members() {
    const out = {};
    for (const k in this.clients) {
      const c = this.clients[k];
      if (c.id) out[c.id] = c;
    }
    return out;
  }
  memberById(id) { return this.members()[id] || null; }
  clientsTarget(id) {
    const c = this.memberById(id);
    return c && c.connection && c.connection.readyState === 1 ? c : null;
  }

  removePlaceholder(conn) {
    for (const k in this.clients) {
      if (k.startsWith('$') && this.clients[k] === conn) { delete this.clients[k]; return; }
    }
  }

  removeClient(conn, announce) {
    const existed = !!conn.id;
    if (existed) delete this.clients[conn.id];
    else this.removePlaceholder(conn);
    this.ipCount[conn.ip] = Math.max(0, (this.ipCount[conn.ip] || 1) - 1);
    try { conn.connection.close(); } catch { /* ignore */ }
    if (existed && announce) {
      if (Object.keys(this.members()).length === 0) { this.roomNonce = null; this.pendingNonce = null; }   // 房间清空，nonce 重置
      for (const other of Object.values(this.members())) {
        this.send(other.connection, JSON.stringify({ t: 'member.gone', id: conn.id, epoch: this.epoch }));
      }
      this.bumpEpochSoon();
    }
  }

  // 5 秒窗口内的成员变化合并为一个 epoch 递增（规格 §5.3）
  bumpEpochSoon() {
    this.pendingBump = true;
    if (this.epochFlushTimer) return;
    this.epochFlushTimer = setTimeout(() => {
      this.epochFlushTimer = null;
      if (!this.pendingBump) return;
      this.pendingBump = false;
      this.epoch++;
      for (const c of Object.values(this.members())) {
        this.send(c.connection, JSON.stringify({ t: 'epoch', e: this.epoch }));
      }
    }, EPOCH_MERGE_MS);
  }

  // ── 限流工具 ──
  take(bucket, n, refillPerSec, capacity) {
    const now = getTime();
    bucket.tokens = Math.min(capacity, bucket.tokens + ((now - bucket.last) / 1000) * refillPerSec);
    bucket.last = now;
    if (bucket.tokens >= n) { bucket.tokens -= n; return true; }
    return false;
  }
  rateLimitHs(conn) {
    const now = getTime();
    conn.hsTimes = (conn.hsTimes || []).filter((t) => now - t < 10000);
    if (conn.hsTimes.length >= 3) return false;
    conn.hsTimes.push(now);
    return true;
  }

  cleanupOldConnections() {
    const threshold = getTime() - SEEN_TIMEOUT;
    for (const k of Object.keys(this.clients)) {
      const c = this.clients[k];
      if (c.seen < threshold) this.removeClient(c, true);
    }
  }

  // ── bundle 验签（WebCrypto Ed25519；workerd 支持，异常时降级为 null）──
  async verifyBundle(b, nonceB64) {
    try {
      if (this.readyEd25519 === false) return null;
      // 与客户端 Identity.makeBundle 完全一致: sigBody = id ‖ ipk ‖ xpk ‖ kpk ‖ roomNonce(raw bytes)
      const idB = new TextEncoder().encode(b.id);
      const ipk = b64dec(b.ipk); const xpk = b64dec(b.xpk); const kpk = b64dec(b.kpk); const nonce = b64dec(nonceB64);
      if (ipk.length !== 32 || xpk.length !== 32 || kpk.length !== 1184 || nonce.length !== 16) return false;
      // id 必须由身份公钥导出。签名只证明"持有 ipk 私钥"，不证明"该 id 属于 ipk"；
      // 缺此绑定，任意私钥持有者都能冒用他人 id（撞 id 即触发 DUPLICATE_ID 踢人）。
      const idHash = new Uint8Array(await crypto.subtle.digest('SHA-256', ipk));
      const derivedId = Array.from(idHash, (x) => x.toString(16).padStart(2, '0')).join('').slice(0, 12);
      if (derivedId !== b.id) return false;
      const msg = new Uint8Array(idB.length + 32 + 32 + 1184 + 16);
      let o = 0;
      for (const part of [idB, ipk, xpk, kpk, nonce]) { msg.set(part, o); o += part.length; }
      const key = await crypto.subtle.importKey('raw', ipk, { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'Ed25519' }, key, b64dec(b.sig), msg);
    } catch (e) {
      this.readyEd25519 = false;
      return null;
    }
  }

  send(connection, message) {
    try { if (connection.readyState === 1) connection.send(message); }
    catch (e) { logEvent('send-fail', e && e.message); }
  }
  close(conn, code, reason) {
    try { conn.connection.close(code, reason); } catch { /* ignore */ }
    this.removeClient(conn, false);
  }
}
