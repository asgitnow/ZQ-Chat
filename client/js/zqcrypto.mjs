// ═══════════════════════════════════════════════════════════════════════
//  ZQ-Chat v2 核心密码学 —— Identity / Session / 填充 / Argon2id 拉伸
//
//  依据《ZQ-Chat-加密协议规格-v2》实施。三处实现约束务必保留：
//   · pad/unpad 以首字节 == 1 判定是否填充，而非按长度：长度 8190~8191
//     的载荷会恰好填满 8192，按长度判定将无法剥离。
//   · ML-KEM 封装方固定为 id 较小一方，防止双端各自封装导致 root 静默不一致。
//   · confirmTag 不混入 epoch：成员变化与 ctag 交换存在竞态，混入会让双方
//     算出不同标签 → 误报"密码错误"。root 随轮换前进，标签仍唯一绑定本次握手。
// ═══════════════════════════════════════════════════════════════════════
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { cpaceInit, cpaceFinish, cpaceContext } from './zqcpace.mjs';

const enc = (s) => (typeof s === 'string' ? new TextEncoder().encode(s) : s);
const dec = (b) => new TextDecoder().decode(b);
const concat = (...a) => {
  const n = a.reduce((s, b) => s + b.length, 0);
  const o = new Uint8Array(n);
  let i = 0; for (const b of a) { o.set(b, i); i += b.length; } return o;
};

// —— base64（浏览器与 Node 通用，不依赖 Buffer）——
const B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
export function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 3) {
    const b = u8[i], c = u8[i + 1], d = u8[i + 2];
    s += B64C[b >> 2] + B64C[((b & 3) << 4) | (c === undefined ? 0 : c >> 4)];
    s += c === undefined ? '=' : B64C[((c & 15) << 2) | (d === undefined ? 0 : d >> 6)];
    s += d === undefined ? '=' : B64C[d & 63];
  }
  return s;
}
export function unb64(str) {
  if (typeof str !== 'string' || /[^A-Za-z0-9+/=]/.test(str)) throw new Error('bad base64');
  const clean = str.replace(/=+$/, '');
  const out = new Uint8Array(Math.floor(clean.length * 3 / 4));
  let p = 0, buffer = 0, bits = 0;
  const rev = (ch) => {
    const i = B64C.indexOf(ch);
    if (i < 0) throw new Error('bad base64 char');
    return i;
  };
  for (let i = 0; i < clean.length; i++) {
    buffer = (buffer << 6) | rev(clean[i]); bits += 6;
    if (bits >= 8) { bits -= 8; out[p++] = (buffer >> bits) & 255; }
  }
  return out.slice(0, p);
}
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

export const KDF = (ikm, salt, info, len = 32) => hkdf(sha256, enc(ikm), enc(salt), enc(info), len);
export const PROTO = 'zqchat/v2';
export const ROOM_NONCE_LEN = 16;

// epoch 跳变步数上限。hs.e 由对端可控且不在握手签名体内，
// 放开后单帧即可让本端做任意轮 HKDF 推进（1e5 即冻结 8s，1e9 永久挂起）。
export const EPOCH_MAX_STEPS = 64;

// ═══════════════ 错误码（规格 §9）═══════════════
export const Err = {
  PASSWORD_MISMATCH: 'PASSWORD_MISMATCH',
  AUTH_FAILED: 'AUTH_FAILED',
  REPLAY: 'REPLAY',
  STATE_DESYNC: 'STATE_DESYNC',
  PEER_UNKNOWN: 'PEER_UNKNOWN',
  MALFORMED: 'MALFORMED',
  STALE_EPOCH: 'STALE_EPOCH',
  BAD_BUNDLE: 'BAD_BUNDLE',
};
export class CryptoError extends Error {
  constructor(code, detail = '') { super(`${code}${detail ? ': ' + detail : ''}`); this.code = code; }
}

// ═══════════════ 填充（规格 §6，含 FIX-PAD）═══════════════
export const PAD_BLOCK = 256;
export const PAD_MAX = 8192;

export function padPayload(bytes) {
  if (bytes.length >= PAD_MAX) return bytes;            // 长载荷不填充
  const target = Math.ceil((bytes.length + 1) / PAD_BLOCK) * PAD_BLOCK;
  const out = new Uint8Array(target);
  out[0] = 1;                                            // 填充标记（JSON 首字节恒为 0x7B/0x5B，绝不冲突）
  out.set(bytes, 1);
  return out;
}
export function unpadPayload(p) {
  if (p.length === 0 || p[0] !== 1) return p;            // FIX-PAD: 按标记判定而非长度
  let end = p.length;
  while (end > 1 && p[end - 1] === 0) end--;
  return p.slice(1, end);
}

// ═══════════════ 密码拉伸（规格 §4.4）═══════════════
export const ARGON2_PARAMS = { t: 2, m: 19456, p: 1, dkLen: 32 };

/** 同步拉伸（Node/测试用；浏览器主线程禁止直接调用，走 argon.worker.js） */
export function stretchArgon2id(password, roomId) {
  return argon2id(enc(password), enc(roomId), ARGON2_PARAMS);
}

// ═══════════════ 身份层（规格 §3 / §4.2）═══════════════
export class Identity {
  constructor(seed) {
    this.sk = seed ? (seed instanceof Uint8Array ? seed : unb64(seed)) : ed25519.utils.randomSecretKey();
    this.pk = ed25519.getPublicKey(this.sk);
    // 12 hex = 48 bit；重连后恒定不变，且必须由本 bundle 的 ipk 导出
    this.id = hex(sha256(this.pk)).slice(0, 12);
    this.seedB64 = b64(this.sk);
  }
  sign(msg) { return ed25519.sign(msg instanceof Uint8Array ? msg : enc(msg), this.sk); }
  static verify(sig, msg, pk) { try { return ed25519.verify(sig, msg, pk); } catch { return false; } }

  /** 加入房间时的密钥包；sigBody = id ‖ ipk ‖ xpk ‖ kpk ‖ roomNonce */
  makeBundle(roomNonceBytes) {
    const xs = x25519.utils.randomSecretKey();
    const kem = ml_kem768.keygen();
    const xpk = x25519.getPublicKey(xs);
    const b = { id: this.id, ipk: b64(this.pk), xpk: b64(xpk), kpk: b64(kem.publicKey) };
    b.sig = b64(this.sign(concat(enc(b.id), this.pk, xpk, kem.publicKey, roomNonceBytes)));
    b._xsk = xs; b._ksk = kem.secretKey;      // 仅本地保留
    return b;
  }
  static verifyBundle(b, roomNonceBytes) {
    if (!b || typeof b.id !== 'string' || !/^[0-9a-f]{12}$/.test(b.id)) return false;
    try {
      const ipk = unb64(b.ipk);
      // id 必须由该 bundle 的身份公钥导出：签名只能证明"持有 ipk 的私钥"，
      // 不能证明"这个 id 属于 ipk"。缺此绑定，持有任意私钥者即可冒用他人 id。
      if (hex(sha256(ipk)).slice(0, 12) !== b.id) return false;
      const body = concat(enc(b.id), ipk, unb64(b.xpk), unb64(b.kpk), roomNonceBytes);
      return Identity.verify(unb64(b.sig), body, ipk);
    } catch { return false; }
  }
  /** 握手材料签名（ADD-HSSIG）：sigHS = "zqchat/v2/hs" ‖ to ‖ roomNonce ‖ ya ‖ kemCt */
  signHS(to, roomNonceBytes, yaBytes, kemCtBytes) {
    return b64(this.sign(concat(enc(`${PROTO}/hs`), enc(to), roomNonceBytes,
      yaBytes || new Uint8Array(0), kemCtBytes || new Uint8Array(0))));
  }
  static verifyHSSig(ipkBytes, sigB64, to, roomNonceBytes, yaBytes, kemCtBytes) {
    try {
      return Identity.verify(unb64(sigB64), concat(enc(`${PROTO}/hs`), enc(to), roomNonceBytes,
        yaBytes || new Uint8Array(0), kemCtBytes || new Uint8Array(0)), ipkBytes);
    } catch { return false; }
  }
}

// ═══════════════ 会话（规格 §4.3–§4.9 / §5）═══════════════
export class Session {
  /** 为某个 peer 准备 CPace（ya 随 hs 消息发出） */
  static prepare(mb, pb, prs, roomId, roomNonceBytes) {
    const { sid, CI } = cpaceContext(roomId, mb.id, pb.id, roomNonceBytes, mb.ipk, pb.ipk, mb.xpk, pb.xpk);
    return { ...cpaceInit(prs, sid, CI), sid, CI };
  }

  /**
   * 建立会话。
   * 封装方（FIX-KEM）：myId < peerId 的一侧封装并回传 kemCt；另一侧解封。
   * kemCt: 收到的对端封装密文；自己是解封方时传入，自己是封装方时传 null。
   */
  static pair(mb, pb, myPrep, peerYa, kemCt, prs, roomId, roomNonceBytes, epoch = 0) {
    const iAmEncap = mb.id < pb.id;
    if (iAmEncap && kemCt) throw new CryptoError(Err.MALFORMED, 'encap side got kemCt');
    if (!iAmEncap && !kemCt) throw new CryptoError(Err.MALFORMED, 'decap side missing kemCt');

    const s = new Session();
    s.myId = mb.id; s.peerId = pb.id; s.roomId = roomId;
    s.roomNonce = roomNonceBytes;
    s.epoch = 0;   // 真正的起始 epoch 由末尾的 rotateTo(epoch) 钉死（见握手 epoch 钉死说明）
    s.authMode = prs === null || (typeof prs === 'string' && prs === '') || (prs && prs.length === 0)
      ? 'no-password' : 'pake';

    const ssX = x25519.getSharedSecret(mb._xsk, unb64(pb.xpk));
    if (ssX.every((x) => x === 0)) throw new CryptoError(Err.MALFORMED, 'low-order x25519 pubkey');
    let ssK;
    if (iAmEncap) {
      const e = ml_kem768.encapsulate(unb64(pb.kpk));
      s.kemCipherText = e.cipherText;      // 必须回传对端
      ssK = e.sharedSecret;
    } else {
      ssK = ml_kem768.decapsulate(kemCt instanceof Uint8Array ? kemCt : unb64(kemCt), mb._ksk);
    }
    const ssP = cpaceFinish(myPrep.scalar, peerYa, myPrep.yaBytes, myPrep.sid, myPrep.CI);
    s.ya = b64(myPrep.yaBytes);

    const sorted = [mb.id, pb.id].sort();   // 字符串字典序
    s._lo = sorted[0]; s._hi = sorted[1];
    s.root = KDF(concat(ssX, ssK, ssP), roomId, `${PROTO}/root${s._lo}${s._hi}`);
    s._rekey();
    s._mkFingerprint();
    // 握手 epoch 钉死：双方以 max(本地, 对端 hs.e) 为起点同步推进链。
    // 成员变化广播存在到达顺序差时，配对时刻不同侧看到的 epoch 可能差 1；
    // 不钉死会导致一侧多轮换、另一侧少轮换 → 密钥链分叉 → 误报密码错误。
    if (epoch > 0) s.rotateTo(epoch, EPOCH_MAX_STEPS);
    return s;
  }

  // —— 密码确认标签（FIX-CONF：不混入 epoch）——
  confirmTag() {
    return b64(KDF(this.root, this.roomId, `${PROTO}/confirm${this._lo}${this._hi}${b64(this.roomNonce)}`, 16));
  }
  verifyConfirm(peerTagB64) {
    const mine = this.confirmTag();
    if (mine.length !== peerTagB64.length) return false;
    let diff = 0;
    for (let i = 0; i < mine.length; i++) diff |= mine.charCodeAt(i) ^ peerTagB64.charCodeAt(i);
    return diff === 0;
  }

  _mkFingerprint() {
    this.fingerprint = hex(KDF(this.root, this.roomId, `${PROTO}/fp${this._lo}${this._hi}`, 30));
  }

  // —— 密钥轮换（规格 §5，epoch 驱动，零往返）——
  rotateTo(newEpoch, maxSteps = EPOCH_MAX_STEPS) {
    if (newEpoch < this.epoch) throw new CryptoError(Err.STALE_EPOCH, `${newEpoch} < ${this.epoch}`);
    if (newEpoch - this.epoch > maxSteps) throw new CryptoError(Err.STATE_DESYNC, 'epoch jump too large');
    while (this.epoch < newEpoch) {
      this.epoch++;
      this._prevRecv = { chain: this.recvChain, seq: this.recvSeq };
      this.root = KDF(this.root, this.roomId, `${PROTO}/rotate${this.epoch}${this._lo}${this._hi}`);
      this._rekey();
    }
    return this.epoch;   // 指纹不变（轮换发生在认证之后）
  }

  _rekey() {
    this.sendChain = KDF(this.root, this.roomId, `${PROTO}/chain${this.myId}${this.peerId}`);
    this.recvChain = KDF(this.root, this.roomId, `${PROTO}/chain${this.peerId}${this.myId}`);
    this.sendSeq = 0; this.recvSeq = 0; this.recvSeen = new Set();
  }
  _msgKeyAt(chain, n) { return KDF(chain, this.roomId, `${PROTO}/msg${n}`); }

  // —— 消息封装（规格 §4.7/§4.8）——
  // aadExtra: 文件分片等应用级认证字段 { fid, vi, tv }，会原样放入线上包供接收端重建 AAD
  encrypt(payload, aadExtra = null) {
    const n = this.sendSeq++;
    const mk = this._msgKeyAt(this.sendChain, n);
    this.sendChain = KDF(this.sendChain, this.roomId, `${PROTO}/chain${n}`);
    const aadObj = { v: 2, from: this.myId, to: this.peerId, room: this.roomId, n, e: this.epoch };
    if (aadExtra) aadObj.f = aadExtra;
    const nonce = randomBytes(24);
    const padded = padPayload(enc(JSON.stringify(payload)));
    const ct = xchacha20poly1305(mk, nonce, enc(JSON.stringify(aadObj))).encrypt(padded);
    mk.fill(0);
    const wire = { n, e: this.epoch, nonce: b64(nonce), ct: b64(ct), to: this.peerId };
    if (aadExtra) wire.f = aadExtra;
    return JSON.stringify(wire);
  }

  decrypt(wireStr) {
    let o;
    try { o = JSON.parse(wireStr); } catch { throw new CryptoError(Err.MALFORMED, 'not JSON'); }
    const { n, e, nonce, ct, to, f } = o;
    if (!Number.isInteger(n) || !Number.isInteger(e) || typeof ct !== 'string' || typeof nonce !== 'string')
      throw new CryptoError(Err.MALFORMED, 'missing fields');
    if (to !== this.myId) throw new CryptoError(Err.REPLAY, 'not addressed to me');
    if (e > this.epoch) this.rotateTo(e);                 // 自动追赶
    if (e < this.epoch) {
      // 上一轮在途消息：用保留的旧链解密（去重由该链自身的 seq 推进保证）
      if (e === this.epoch - 1 && this._prevRecv) return this._decryptWith(this._prevRecv, n, nonce, ct, e, f);
      throw new CryptoError(Err.STALE_EPOCH, `epoch ${e} < ${this.epoch}`);
    }
    // 本轮去重必须在本轮状态内判定：若先于轮次分支检查，
    // 上一轮同序号在途消息会被本轮 recvSeen 误杀，故去重必须在轮次分支内判定
    if (this.recvSeen.has(n)) throw new CryptoError(Err.REPLAY, `seq ${n} used`);
    return this._decryptWith(this, n, nonce, ct, e, f);
  }

  _decryptWith(state, n, nonce, ct, e, f) {
    // 上一轮状态对象字段是 {chain, seq}，本轮是 {recvChain, recvSeq}，
    // 两处混用会让 prev 链从未真正生效
    const curSeq = state.seq === undefined ? state.recvSeq : state.seq;
    if (n < curSeq - 64) throw new CryptoError(Err.REPLAY, 'too old');
    if (n >= curSeq + 4096) throw new CryptoError(Err.STATE_DESYNC, 'seq jump too large');
    let chain = state.chain ?? state.recvChain;
    let seq = curSeq;
    while (seq <= n) {
      const mk = this._msgKeyAt(chain, seq);
      if (seq === n) {
        const aadObj = { v: 2, from: this.peerId, to: this.myId, room: this.roomId, n, e };
        if (f) aadObj.f = f;
        let pt;
        try {
          pt = xchacha20poly1305(mk, unb64(nonce), enc(JSON.stringify(aadObj))).decrypt(unb64(ct));
        } catch {
          mk.fill(0);
          throw new CryptoError(Err.AUTH_FAILED);
        }
        mk.fill(0);
        chain = KDF(chain, this.roomId, `${PROTO}/chain${n}`);
        seq = n + 1;
        if (state === this) { this.recvChain = chain; this.recvSeq = seq; this.recvSeen.add(n); }
        else { state.chain = chain; state.seq = seq; }
        return JSON.parse(dec(unpadPayload(pt)));
      }
      mk.fill(0);      // 跳过序号派生的中间消息密钥同样清零
      chain = KDF(chain, this.roomId, `${PROTO}/chain${seq}`);
      seq++;
    }
    throw new CryptoError(Err.REPLAY, 'seq consumed');
  }
}

// ═══════════════ 令牌桶（规格 §7.5，服务器端复用）═══════════════
export class TokenBucket {
  constructor(capacity, refillPerSec) {
    this.capacity = capacity; this.refill = refillPerSec;
    this.tokens = capacity; this.last = Date.now();
  }
  take(n = 1) {
    const now = Date.now();
    this.tokens = Math.min(this.capacity, this.tokens + ((now - this.last) / 1000) * this.refill);
    this.last = now;
    if (this.tokens >= n) { this.tokens -= n; return true; }
    return false;
  }
}

export { concat, enc, dec, hex };
