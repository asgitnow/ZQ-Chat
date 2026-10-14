// ═══════════════════════════════════════════════════════════════════════
//  ZQ-Chat v2 —— CPace 风格 PAKE（Ristretto255 群）
//
//  基于 zqchat-crypto-audit 参考实现，含两处实施修正：
//   1. CI 中身份公钥顺序改为「按 id 排序后的对应公钥」（参考实现按 ipk 字节
//      排序，与规格 §4.3 "ipk_lo/ipk_hi 为对应排序的身份公钥" 不符）
//   2. 明确本构造是 CPace 的派生变体（lp 宽度、生成元输入顺序、ISK 中
//      ya/yb 采用字节排序而非角色序），与 RFC 9528 并非逐字节一致
// ═══════════════════════════════════════════════════════════════════════
import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

const P = ristretto255.Point;
const enc = (s) => (typeof s === 'string' ? new TextEncoder().encode(s) : s);
// lp: 4 字节小端长度前缀（与规格 §2 定义一致；注意规格抬头"大端"仅指 wire 整数字段）
const LE = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
const concat = (...a) => {
  const n = a.reduce((s, b) => s + b.length, 0);
  const o = new Uint8Array(n);
  let i = 0; for (const b of a) { o.set(b, i); i += b.length; } return o;
};
const lp = (b) => concat(LE(b.length), b);

const DSI = enc('CPaceRistretto255-1');
const cmpBytes = (a, b) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};

/** 计算 CPace 生成元 G（双方独立算出同一个点） */
export function cpaceGenerator(prs, sid, CI) {
  return ristretto255_hasher.hashToCurve(
    concat(DSI, lp(enc(prs)), lp(enc(sid)), lp(enc(CI)))
  );
}

/** 发起一次 CPace：返回 { yaBytes(公开), scalar(本地秘密), G } */
export function cpaceInit(prs, sid, CI) {
  const G = cpaceGenerator(prs, sid, CI);
  const scalar = ristretto255_hasher.hashToScalar(randomBytes(64));
  const ya = G.multiply(scalar);
  return { yaBytes: ya.toBytes(), scalar, G };
}

/** 收到对方 ya 后计算共享密钥 ISK */
export function cpaceFinish(myScalar, peerYaBytes, myYaBytes, sid, CI) {
  const Yb = P.fromBytes(peerYaBytes);          // 非规范点会抛异常（含全零）
  if (Yb.is0()) throw new Error('CPace: peer sent identity element');
  const K = Yb.multiply(myScalar);
  if (K.is0()) throw new Error('CPace: degenerate shared point');
  const [y1, y2] = cmpBytes(myYaBytes, peerYaBytes) <= 0
    ? [myYaBytes, peerYaBytes] : [peerYaBytes, myYaBytes];
  return sha512(concat(
    DSI, enc('ISK'), lp(enc(sid)), lp(y1), lp(y2), lp(K.toBytes()), lp(enc(CI))
  ));
}

/**
 * sid / CI 构造 —— 双方可确定性独立计算，零额外往返
 * roomNonce: 房间新鲜值(16B)，与「epoch 轮换计数」是两个概念
 */
export function cpaceContext(room, idA, idB, roomNonce, ipkA, ipkB) {
  const pair = idA <= idB ? [[idA, ipkA], [idB, ipkB]] : [[idB, ipkB], [idA, ipkA]];
  const [lo, hi] = pair.map(([id]) => id);
  const [ipkLo, ipkHi] = pair.map(([, ipk]) => ipk);
  return {
    sid: sha512(concat(enc('zqchat/v2/sid'), lp(enc(room)), lp(enc(lo)), lp(enc(hi)), lp(enc(roomNonce)))),
    CI: concat(enc('zqchat/v2/CI'), lp(enc(room)), lp(enc(lo)), lp(enc(hi)), lp(enc(ipkLo)), lp(enc(ipkHi))),
  };
}
