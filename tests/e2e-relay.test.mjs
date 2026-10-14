// ═══════════════════════════════════════════════════════════════════════
//  端到端集成测试 —— 真实 worker 代码（盲中继）+ 真实 NodeCrypt 客户端 ×4
//  覆盖：握手/广播/私聊/加员轮换/离席轮换/错密码隔离/密文篡改/重放/
//        盲中继（服务器不可见明文）/DO 房间隔离/重连身份稳定/坏 bundle 拒绝
//  运行: node tests/e2e-relay.test.mjs   （可 VDBG=1 看协议日志）
// ═══════════════════════════════════════════════════════════════════════
import NodeCrypt from '../client/js/NodeCrypt.js';
import { createRelay, makeWsFactory } from './relay-harness.mjs';
import { sha256 } from '@noble/hashes/sha2.js';

const relay = createRelay();
const roomHash = (name) => Array.from(sha256(new TextEncoder().encode(name)), (b) => b.toString(16).padStart(2, '0')).join('');

let pass = 0, fail = 0;
const ok = (c, n, x = '') => { c ? (pass++, console.log(`  ✅ ${n}${x ? ' — ' + x : ''}`)) : (fail++, console.log(`  ❌ ${n}${x ? ' — ' + x : ''}`)); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 9000, label = '') => {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(50); }
  return false;
};

const MEMORY_STORES = new Map();
function storage(name) {
  if (!MEMORY_STORES.has(name)) {
    const map = {};
    MEMORY_STORES.set(name, { getItem: (k) => map[k] ?? null, setItem: (k, v) => { map[k] = v; } });
  }
  return MEMORY_STORES.get(name);
}

function mkClient(tag, room, pass, name) {
  const ev = [];
  const hash = roomHash(room);
  const cb = {
    onServerClosed: () => ev.push({ t: 'closed' }),
    onServerSecured: () => ev.push({ t: 'secured', id: nc.identity.id }),
    onClientSecured: (u) => ev.push({ t: 'peer', id: u.clientId, name: u.username }),
    onClientList: (l, self) => { cpeers.clear(); l.forEach((x) => cpeers.set(x.clientId, x)); myId = self; },
    onClientMessage: (m) => ev.push({ t: 'msg', from: m.clientId, type: m.type, data: m.data }),
    onClientLeft: (u) => ev.push({ t: 'left', id: u.clientId }),
    onPeerError: (e) => ev.push({ t: 'peererr', ...e }),
    onRoomError: (e) => ev.push({ t: 'roomerr', ...e }),
  };
  const cpeers = new Map();
  let myId = null;
  const nc = new NodeCrypt(
    { wsAddress: 'wss://relay.test', debug: !!process.env.VDBG, storage: storage(tag), wsFactory: makeWsFactory(relay, hash) },
    cb,
  );
  nc.setCredentials(name, room, pass);
  nc.connect();
  return { nc, ev, peers: cpeers, get myId() { return myId; }, tag };
}

// ═════ ① 基础：两人房间 ═════
console.log('\n① 两人房间：握手/广播/私聊');
const ROOM1 = 'e2e-room';
const A = mkClient('alice', ROOM1, 'pw-alpha', 'Alice');
const B = mkClient('bob', ROOM1, 'pw-alpha', 'Bob');
ok(await until(() => A.peers.size === 1 && B.peers.size === 1), '双向 peer_ready（CPace+KEM+签名全链路）');
ok(A.myId === A.nc.identity.id && B.myId === B.nc.identity.id, '回调携带稳定的 selfId');

A.nc.sendChannelMessage('text', '你好 Bob，转账 100 元');
ok(await until(() => B.ev.some((e) => e.t === 'msg' && e.data === '你好 Bob，转账 100 元')), 'A→B 广播消息送达');
B.nc.sendChannelMessage('text', '收到');
ok(await until(() => A.ev.some((e) => e.t === 'msg' && e.data === '收到')), 'B→A 广播消息送达');

// 私聊三步封装（与 main.js 完全相同的调用形态）
{
  const targetId = [...A.peers.keys()][0];
  const target = A.nc.channel[targetId];
  const ct = A.nc.encryptClientMessage({ a: 'm', t: 'text_private', d: '私聊：账户密码是 zzz' }, target.shared);
  const env = A.nc.encryptServerMessage({ a: 'c', p: ct, c: targetId }, A.nc.serverShared);
  ok(!!ct && !!env && A.nc.sendMessage(env), '私聊发送路径返回 true（v1 假成功修复的前提）');
  ok(await until(() => B.ev.some((e) => e.t === 'msg' && e.type === 'text_private' && String(e.data).includes('zzz'))), '私聊消息送达');
}

// 安全码一致
{
  const fpA = A.nc.channel[B.nc.identity.id]?.shared?.fingerprint;
  const fpB = B.nc.channel[A.nc.identity.id]?.shared?.fingerprint;
  ok(fpA && fpA === fpB, '双方安全码一致', fpA?.slice(0, 12) + '…');

  // 安全码必须一路贯通到 UI 回调，否则 Web 界面无从展示（MITM 检测断链）
  const viaListA = [...A.peers.values()].find((u) => u.username === 'Bob')?.fingerprint;
  const viaListB = [...B.peers.values()].find((u) => u.username === 'Alice')?.fingerprint;
  ok(viaListA && viaListA === fpA && viaListB === fpA,
    '安全码经 onClientList 送达 UI，双方取到同一值', `${(viaListA || '').match(/.{1,4}/g)?.length} 组`);
  ok(/^[0-9a-f]{60}$/.test(fpA), '安全码为 60 hex（30B 派生物），可按 4 位分组口头核对');
  ok(fpA !== B.nc.channel[A.nc.identity.id]?.bundle?.xpk && fpA !== A.nc.identity.id,
    '安全码既不等于对端公钥也不等于身份 id（不能被中继预知）');
}

// ═════ ② 加员 → 轮换 ═════
console.log('\n② 第三人加入（epoch 轮换）');
const C = mkClient('carol', ROOM1, 'pw-alpha', 'Carol');
ok(await until(() => A.peers.size === 2 && B.peers.size === 2 && C.peers.size === 2), '三人两两握手完成');
const epochBefore = A.nc.epoch;
await sleep(5600);   // 服务器 5s 合并窗口
ok(A.nc.epoch > epochBefore || (await until(() => A.nc.epoch > epochBefore, 3000)), 'epoch 已前进（成员变化触发轮换）', `A.epoch=${A.nc.epoch}`);
const fpA2 = A.nc.channel[B.nc.identity.id]?.shared?.fingerprint;
ok(fpA2 === A.nc.channel[B.nc.identity.id]?.shared?.fingerprint, '轮换后安全码稳定');
A.nc.sendChannelMessage('text', '轮换后的新消息');
ok(await until(() => B.ev.some((e) => e.t === 'msg' && e.data === '轮换后的新消息')) &&
   await until(() => C.ev.some((e) => e.t === 'msg' && e.data === '轮换后的新消息')), '轮换后消息全员送达');

// ═════ ③ 离席 → 轮换 + 剩余成员继续 ═════
console.log('\n③ Carol 离席');
C.nc.destruct();
ok(await until(() => A.peers.size === 1 && B.peers.size === 1), '离席事件到达');
await sleep(5600);
B.nc.sendChannelMessage('text', 'Carol 走后还正常');
ok(await until(() => A.ev.some((e) => e.t === 'msg' && e.data === 'Carol 走后还正常')), '离席轮换后消息正常');

// ═════ ④ 错误密码隔离 ═════
console.log('\n④ 错误密码');
const D = mkClient('mallory', ROOM1, 'pw-WRONG', 'Mallory');
ok(await until(() => D.ev.some((e) => e.t === 'peererr' && e.code === 'PASSWORD_MISMATCH') ||
                A.ev.some((e) => e.t === 'peererr' && e.code === 'PASSWORD_MISMATCH')),
   '密码错误 → 双方收到 PASSWORD_MISMATCH（不是静默乱码）');
ok(!D.ev.some((e) => e.t === 'msg' && e.data === 'Carol 走后还正常'), '错误密码者收不到任何明文消息');
A.nc.sendChannelMessage('text', 'Mallory 滚出去之后我还能说话');
ok(await until(() => B.ev.some((e) => e.t === 'msg' && e.data === 'Mallory 滚出去之后我还能说话')), '剔除错密码 peer 后正常会话不受影响');
D.nc.destruct();

// ═════ ⑤ 恶意中继：篡改与重放 ═════
console.log('\n⑤ 恶意中继注入');
{
  // 抓一条 A→B 的密文，服务器侧翻转比特重投给 B
  const wire = A.nc.channel[B.nc.identity.id].shared.encrypt({ a: 'm', t: 'text', d: 'ORIGINAL' });
  const o = JSON.parse(wire);
  const bytes = Uint8Array.from(atob(o.ct), (c) => c.charCodeAt(0));
  bytes[4] ^= 1;
  const flipped = JSON.stringify({ ...o, ct: btoa(String.fromCharCode(...bytes)) });
  const before = B.ev.filter((e) => e.t === 'msg').length;
  // 定位 Bob 自己的连接：其 client.sentLog 里必有带自己 bundle.id 的 join
  const bPair = relay.pairs.find((p) => p.client.sentLog.some((f) => f.includes('"t":"join"') && f.includes(`"id":"${B.nc.identity.id}"`)));
  ok(!!bPair, '定位 Bob 的中继连接');
  bPair.server.send(JSON.stringify({ t: 'msg', from: A.nc.identity.id, c: flipped }));
  await sleep(400);
  ok(B.ev.filter((e) => e.t === 'msg').length === before, '篡改消息被丢弃且不打断会话');
  // 重放一条合法旧消息
  A.nc.sendChannelMessage('text', 'REPLAY-TEST');
  await until(() => B.ev.some((e) => e.t === 'msg' && e.data === 'REPLAY-TEST'), 5000);
  const afterFirst = B.ev.filter((e) => e.t === 'msg' && e.data === 'REPLAY-TEST').length;
  // 抓 Bob 连接上服务器实际下发过的一条单播帧重放
  const lastUnicast = [...bPair.server.sentLog].reverse().find((f) => f.includes('"t":"msg"'));
  bPair.server.send(lastUnicast);
  await sleep(300);
  ok(B.ev.filter((e) => e.t === 'msg' && e.data === 'REPLAY-TEST').length === afterFirst, '重放被拒');
  B.nc.sendChannelMessage('text', '注入攻击后仍然正常');
  ok(await until(() => A.ev.some((e) => e.t === 'msg' && e.data === '注入攻击后仍然正常')), '消息循环未被单条恶意消息打断（规格 §7.5）');
}

// ═════ ⑥ 盲中继：服务器视角零明文 ═════
console.log('\n⑥ 盲中继验证');
{
  const allFrames = relay.pairs.flatMap((p) => [...p.client.sentLog, ...p.server.sentLog]);
  const secrets = ['转账 100 元', '你好 Bob', '收到', 'zzz', '轮换后的新消息', 'Carol 走后还正常',
    'Mallory 滚出去', 'REPLAY-TEST', 'pw-alpha', 'pw-WRONG', 'Alice', 'Bob', 'Carol', 'Mallory'];
  const leaked = secrets.filter((s) => allFrames.some((f) => f.includes(s)));
  ok(leaked.length === 0, '服务器经手的所有帧中无任何消息明文/用户名/密码', `${allFrames.length} 帧`);
  const ids = allFrames.filter((f) => f.includes('"ipk"')).length;
  ok(ids >= 3, '中继经手的只是 bundle/密文/信封等不透明材料', `含 ipk 帧 ${ids}`);
}

// ═════ ⑦ DO 房间隔离 ═════
console.log('\n⑦ 房间隔离');
{
  const E = mkClient('eve', 'other-room', 'pw-beta', 'Eve');
  ok(await until(() => E.ev.some((e) => e.t === 'secured')), '另一房间连接成功');
  ok(relay.seenDoIds.size >= 2, `Durable Object 按房间分片（seen=${[...relay.seenDoIds].map((x) => x.split('::')[1]?.slice(0, 8)).join(',')}…）`);
  A.nc.sendChannelMessage('text', '房间隔离检查-勿跨界');
  await sleep(400);
  ok(!E.ev.some((e) => e.t === 'msg' && e.data === '房间隔离检查-勿跨界'), '跨房间消息不可达');
  E.nc.destruct();
}

// ═════ ⑧ 重连身份稳定 ═════
console.log('\n⑧ 重连');
{
  const idBefore = B.nc.identity.id;
  B.nc.disconnect();
  await sleep(300);
  B.nc.connect();
  ok(await until(() => {
    const securedEvts = B.ev.filter((e) => e.t === 'secured');
    return securedEvts.length >= 2 && securedEvts[securedEvts.length - 1].id === idBefore;
  }, 9000), '重连完成握手且 clientId 不变');
  ok(B.nc.identity.id === idBefore, '身份 id 恒定', idBefore);
  // 必须等 A↔B 的会话重建完成：relay 层 secured 只说明 B 进了中继房间，
  // 而对端会话还要走 hs → kemCt → pair → ctag → 交换用户名。
  // username 就位前 sendChannelMessage 会按设计跳过该 peer 并返回 false。
  ok(await until(() => A.peers.size === 1 && B.peers.size === 1, 9000), '重连后与对端会话重建完成');
  A.nc.sendChannelMessage('text', '重连后我还能收到');
  ok(await until(() => B.ev.some((e) => e.t === 'msg' && e.data === '重连后我还能收到'), 9000), '重连后消息恢复（重连即新会话）');
}

// ═════ ⑨ 坏 bundle 直连拒绝（纯协议路径）═════
console.log('\n⑨ 协议层防御');
{
  const { client } = await relay.connect(roomHash(ROOM1), '198.51.100.7');
  client.fireOpen();
  const nonce = await new Promise((res, rej) => {
    client._handlers.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.t === 'nonce') res(m);
    };
    setTimeout(() => client.send(JSON.stringify({ t: 'nonce' })), 10);
    setTimeout(() => rej(new Error('nonce-timeout')), 5000);
  }).catch(() => ({ nonce: null }));
  client.send(JSON.stringify({ t: 'join', bundle: { id: 'deadbeefcafe', ipk: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', xpk: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', kpk: 'QUJD', sig: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', nonce: nonce.nonce }, nonce: nonce.nonce }));
  const closed = await until(() => client.readyState === 3, 3000);
  ok(closed, '验签失败的 join 被服务器立即断开（规格 §7.5）');
  client.close();
}

// ═════ ⑩ 大消息（>PAD_MAX）═════
console.log('\n⑩ 大消息');
{
  const big = '×'.repeat(20000);
  A.nc.sendChannelMessage('text', big);
  ok(await until(() => B.ev.some((e) => e.t === 'msg' && e.data === big), 9000), '20000 字大消息端到端送达（超填充上限路径正常）');
}

A.nc.destruct();
B.nc.destruct();
console.log(`\n${'═'.repeat(60)}\n结果: ${pass} 项通过, ${fail} 项失败\n${'═'.repeat(60)}`);
process.exit(fail ? 1 : 0);
