// ═══════════════════════════════════════════════════════════════════════
//  ZQ-Chat v2 —— CPace 变体 PAKE
//
//  对齐：draft-irtf-cfrg-cpace-21，密码套件 CPACE-RISTR255-SHA512
//  （G = G_Ristretto255，H = SHA-512，见草案 §8.3）
//
//  本模块实现 CPace 全部规范函数，未做任何简化：
//    prepend_len / lv_cat / o_cat / generator_string / calculate_generator
//    / sample_scalar / scalar_mult_vfy / transcript_ir / transcript_oc
//  与草案的逐项对应及本项目的取值见 doc/cpace-alignment.md。
//  对齐情况由 tests/crypto.test.mjs 用草案 Appendix B.3 的官方测试向量验证。
//
//  与规范的差异仅两处，均为应用层输入的构造（不改变规范函数本身）：
//    · CI 与 sid 由本项目的房间/身份上下文构造，见 cpaceContext()
//    · 采用对称设置（transcript_oc），因握手无强制发起方/响应方顺序
// ═══════════════════════════════════════════════════════════════════════
import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes, hexToBytes } from '@noble/hashes/utils.js';

const P = ristretto255.Point;
const enc = (s) => (typeof s === 'string' ? new TextEncoder().encode(s) : s);
const concat = (...a) => {
	const n = a.reduce((s, b) => s + b.length, 0);
	const o = new Uint8Array(n);
	let i = 0; for (const b of a) { o.set(b, i); i += b.length; } return o;
};
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
const leToBigInt = (b) => { let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return x; };
const cmpBytes = (a, b) => {
	for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
	return a.length - b.length;
};

const B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
/** base64 → 原始字节。与 zqcrypto.unb64 同语义，独立于此以避免循环依赖。 */
function b64ToBytes(str) {
	if (typeof str !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(str)) throw new Error('bad base64');
	const clean = str.replace(/=+$/, '');
	const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
	let p = 0, buf = 0, bits = 0;
	for (let i = 0; i < clean.length; i++) {
		const v = B64C.indexOf(clean[i]);
		if (v < 0) throw new Error('bad base64 char');
		buf = (buf << 6) | v; bits += 6;
		if (bits >= 8) { bits -= 8; out[p++] = (buf >> bits) & 255; }
	}
	return out.subarray(0, p);
}

// —— G_Ristretto255 / H=SHA-512 常量（草案 §6.2、§8.3）——
export const DSI = enc('CPaceRistretto255');
const DSI_ISK = enc('CPaceRistretto255_ISK');
const H_S_IN_BYTES = 128;        // SHA-512 输入块大小
const FIELD_SIZE_BYTES = 32;
const GROUP_SIZE_BITS = 252;

// ═══════════════ 草案 §6.3 字符串运算 ═══════════════

/** prepend_len：LEB128 变长长度前缀（草案 §6.3、附录 A.1.1） */
export function prependLen(bytes) {
	let n = bytes.length;
	const out = [];
	do {
		let b = n & 0x7f;
		n >>>= 7;
		if (n !== 0) b |= 0x80;
		out.push(b);
	} while (n !== 0);
	return new Uint8Array([...out, ...bytes]);
}

/** lv_cat：各分量前置长度后拼接（草案 §6.3、附录 A.1.3） */
export function lvCat(...arrs) {
	return concat(...arrs.map(prependLen));
}

/** o_cat：字典序较大者在前，并以 b"oc" 为域分隔前缀（草案 §6.3、附录 A.3.6） */
export function oCat(a, b) {
	const [x, y] = cmpBytes(a, b) <= 0 ? [b, a] : [a, b];
	return concat(enc('oc'), x, y);
}

/** transcript_ir：initiator-responder 设置下的协议记录（草案 §6.3） */
export const transcriptIr = (Ya, ADa, Yb, ADb) => concat(lvCat(Ya, ADa), lvCat(Yb, ADb));

/** transcript_oc：对称设置下的协议记录（草案 §6.3） */
export const transcriptOc = (Ya, ADa, Yb, ADb) => oCat(lvCat(Ya, ADa), lvCat(Yb, ADb));

// ═══════════════ 草案 §8.1 / §8.3 生成元 ═══════════════

/**
 * generator_string(DSI, PRS, CI, sid, s_in_bytes)
 * = lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)
 * len_zpad 使 DSI‖PRS‖zpad 恰好填满哈希输入的首个块。
 */
export function generatorString(DSIbytes, PRS, CI, sid, sInBytes = H_S_IN_BYTES) {
	const lenZpad = Math.max(0, sInBytes - prependLen(PRS).length - prependLen(DSIbytes).length - 1);
	return lvCat(DSIbytes, PRS, new Uint8Array(lenZpad), CI, sid);
}

/** G.calculate_generator(H, PRS, CI, sid)：先哈希到 2×field_size，再做元素派生（草案 §8.3） */
export function calculateGenerator(PRS, CI, sid) {
	const genStr = generatorString(DSI, PRS, CI, sid, H_S_IN_BYTES);
	const genStrHash = sha512(genStr);                       // = 2 * FIELD_SIZE_BYTES = 64
	// element_derivation = RFC 9496 §4.3.4 的 from_uniform_bytes（输入恰好 64 字节）
	return ristretto255_hasher.deriveToCurve(genStrHash);
}

// ═══════════════ 草案 §8.3 标量与群运算 ═══════════════

/**
 * G.sample_scalar()（草案 §8.3 推荐实现）：
 * 取 group_size_bytes 随机字节，清除高于 group_size_bits 的比特，按小端解释为整数。
 */
export function sampleScalar() {
	const b = randomBytes(FIELD_SIZE_BYTES);
	b[FIELD_SIZE_BYTES - 1] &= 0xff >> GROUP_SIZE_BITS;
	return leToBigInt(b);
}

/** G.scalar_mult_vfy：解码失败或退化为单位元时抛错（草案要求调用方在 K=G.I 时中止） */
export function scalarMultVfy(scalar, peerYaBytes) {
	let X;
	try { X = P.fromBytes(peerYaBytes); }
	catch { throw new Error('CPace: decode of peer share failed'); }
	if (X.is0()) throw new Error('CPace: peer sent identity element');
	const K = X.multiply(scalar);
	if (K.is0()) throw new Error('CPace: degenerate shared point');
	return K.toBytes();
}

// ═══════════════ 本项目封装的规范接口 ═══════════════

/**
 * 本项目的 CPace 输入构造（应用层，规范未规定其编码）：
 *   PRS = Argon2id(密码, roomId)      —— 空密码时为空字节串
 *   CI  = 绑定双方身份与房间的通道标识（不入线，双方独立导出）
 *   sid = 绑定本房间内本次加入的会话标识
 *
 * 规范 §10.1 要求将当事方标识并入 CI —— 此处用 id 与 ipk 双向绑定，
 * 中继替换成员 bundle 时双方 CI 不一致，握手直接失败。
 * 规范 §4.1 要求 sid 为本次通信会话所特有 —— 此处并入双方 xpk，
 * 故每次加入（xpk 每次重新生成）都得到新的 sid。
 */
export function cpaceContext(room, idA, idB, roomNonce, ipkA, ipkB, xpkA, xpkB) {
	const pair = idA <= idB ? [[idA, ipkA, xpkA], [idB, ipkB, xpkB]] : [[idB, ipkB, xpkB], [idA, ipkA, xpkA]];
	// 必须解码为原始字节：prepend_len 面向字节串，若直接传字符串会被逐字符转数字，
	// 字母变 0、数字变字面值 —— 不同 id 会产生相同编码，身份绑定（草案 §10.1）随之失效。
	const [lo, hi] = pair.map(([id]) => hexToBytes(id));           // 12 hex → 6 字节
	const [ipkLo, ipkHi] = pair.map(([, k]) => b64ToBytes(k));      // 32 字节公钥
	const [xpkLo, xpkHi] = pair.map(([, , k]) => b64ToBytes(k));
	return {
		sid: sha512(lvCat(enc('zqchat/v2/sid'), enc(room), lo, hi, roomNonce, xpkLo, xpkHi)),
		CI: lvCat(enc('zqchat/v2/CI'), enc(room), lo, hi, ipkLo, ipkHi),
	};
}

/** 发起一次 CPace：返回 { yaBytes(公开), scalar(本地秘密), G(生成元) } */
export function cpaceInit(prs, sid, CI) {
	const G = calculateGenerator(prs, CI, sid);
	const scalar = sampleScalar();
	const ya = G.multiply(scalar);
	return { yaBytes: ya.toBytes(), scalar, G };
}

/**
 * 收到对方 ya 后计算共享中间密钥 ISK（草案 §7.2）。
 * mode: 'symmetric' 用 transcript_oc（本项目默认）；'ir' 用 transcript_ir。
 * ADa / ADb 为关联数据，本项目不使用，传空字节串。
 */
export function cpaceFinish(myScalar, peerYaBytes, myYaBytes, sid, CI, ADa = EMPTY, ADb = EMPTY, mode = 'symmetric') {
	const K = scalarMultVfy(myScalar, peerYaBytes);
	const transcript = mode === 'ir'
		? transcriptIr(myYaBytes, ADa, peerYaBytes, ADb)
		: transcriptOc(myYaBytes, ADa, peerYaBytes, ADb);
	return sha512(concat(lvCat(DSI_ISK, sid, K), transcript));
}

const EMPTY = new Uint8Array(0);

/** 仅用于测试：按固定标量复现草案测试向量 */
export { ristretto255, ristretto255_hasher, sha512, hex, concat, enc };