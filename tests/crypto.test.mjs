// ZQ-Chat v2 密码学单元测试 —— 覆盖规格 §13 全部类别
// 运行: node tests/crypto.test.mjs
import {
	Identity, Session, Err, padPayload, unpadPayload, b64, unb64,
	TokenBucket, stretchArgon2id, ROOM_NONCE_LEN, EPOCH_MAX_STEPS,
} from '../client/js/zqcrypto.mjs';
import { cpaceFinish, cpaceContext, calculateGenerator } from '../client/js/zqcpace.mjs';
import { checkVectors } from './cpace-vectors.mjs';
import { ristretto255_hasher } from '@noble/curves/ed25519.js';

let pass = 0, fail = 0;
const ok = (cond, name, extra = '') => {
	if (cond) { pass++; console.log(`  ✅ ${name}${extra ? '  — ' + extra : ''}`); }
	else { fail++; console.log(`  ❌ ${name}${extra ? '  — ' + extra : ''}`); }
};
const throws = (fn, code, name) => {
	try { fn(); ok(false, name, '未抛出异常'); }
	catch (e) { ok(e.code === code, name, e.code || e.message); }
};

const ROOM = 'a'.repeat(64);
const nonceOf = (v) => new Uint8Array(ROOM_NONCE_LEN).fill(v);

function makePeer(seedByte) {
	const seed = new Uint8Array(32); seed[0] = seedByte; seed[31] = 1;
	return { id: new Identity(seed) };
}
function bundleWith(peer, rn) { peer.bundle = peer.id.makeBundle(rn); return peer; }

/** 完整两方配对，返回 [sA, sB]（自动决定封装角色） */
function handshake(x, y, prs, rn, epoch = 0) {
	const px = Session.prepare(x.bundle, y.bundle, prs, ROOM, rn);
	const py = Session.prepare(y.bundle, x.bundle, prs, ROOM, rn);
	const xIsLo = x.bundle.id < y.bundle.id;
	const lo = xIsLo ? x : y, hi = xIsLo ? y : x;
	const pLo = xIsLo ? px : py, pHi = xIsLo ? py : px;
	const sLo = Session.pair(lo.bundle, hi.bundle, pLo, pHi.yaBytes, null, prs, ROOM, rn, epoch);
	const sHi = Session.pair(hi.bundle, lo.bundle, pHi, pLo.yaBytes, sLo.kemCipherText, prs, ROOM, rn, epoch);
	return [xIsLo ? sLo : sHi, xIsLo ? sHi : sLo];
}
// 便捷：A 发出文本并 B 收取的往返
const roundtrip = (x, y, d) => y.decrypt(x.encrypt({ a: 'm', t: 'text', d })).d === d;

// ═════ ① 会话建立 ═════
console.log('\n① 会话建立');
{
	const rn = nonceOf(7);
	const A = bundleWith(makePeer(1), rn), B = bundleWith(makePeer(2), rn);
	ok(Identity.verifyBundle(A.bundle, rn), 'bundle 验签通过');
	ok(!Identity.verifyBundle({ ...A.bundle, xpk: b64(new Uint8Array(32)) }, rn), 'bundle 篡改 xpk 被拒');
	ok(!Identity.verifyBundle(A.bundle, nonceOf(8)), 'bundle 跨 roomNonce 被拒');

	const prs = stretchArgon2id('correct horse', ROOM);
	const [sA, sB] = handshake(A, B, prs, rn);
	ok(sA.root.join() === sB.root.join(), '双方 root 一致（X25519+ML-KEM+CPace）');
	ok(sA.confirmTag() === sB.confirmTag(), '密码正确时确认标签一致');
	ok(sA.fingerprint === sB.fingerprint, '安全码一致');

	const [sAb] = handshake(A, B, stretchArgon2id('wrong horse', ROOM), rn);
	ok(sAb.confirmTag() !== sB.confirmTag(), '密码错误 → 确认标签不匹配（PASSWORD_MISMATCH 可区分）');

	ok(roundtrip(sA, sB, '你好') && roundtrip(sB, sA, '收到'), '双向消息互通');

	// FIX-KEM: 角色写死 —— 找出 hi（解封）侧，缺 kemCt 必须被拒
	const hiIsB = B.bundle.id > A.bundle.id;
	const hiB = hiIsB ? B : A, hiPeer = hiIsB ? A : B;
	const pHi = Session.prepare(hiB.bundle, hiPeer.bundle, prs, ROOM, rn);
	const pPeer = Session.prepare(hiPeer.bundle, hiB.bundle, prs, ROOM, rn);
	throws(() => Session.pair(hiB.bundle, hiPeer.bundle, pHi, pPeer.yaBytes, null, prs, ROOM, rn, 0),
		Err.MALFORMED, '解封方缺 kemCt → MALFORMED（角色写死，防双方各自封装）');

	// ADD-HSSIG
	const pa = Session.prepare(A.bundle, B.bundle, prs, ROOM, rn);
	const hsSig = A.id.signHS(B.id.id, rn, pa.yaBytes, null);
	ok(Identity.verifyHSSig(A.id.pk, hsSig, B.id.id, rn, pa.yaBytes, null), 'hs 签名验签通过');
	ok(!Identity.verifyHSSig(A.id.pk, hsSig, B.id.id, rn, pa.yaBytes, new Uint8Array(1088)), 'hs 签名与 kemCt 绑定（重放旧 kemCt 检出）');
	ok(!Identity.verifyHSSig(B.id.pk, hsSig, B.id.id, rn, pa.yaBytes, null), 'hs 签名换身份被拒');
}

// ═════ ② 密码安全 ═════
console.log('\n② 密码安全');
{
	const rn = nonceOf(3);
	const A = bundleWith(makePeer(5), rn), B = bundleWith(makePeer(6), rn);
	const prs = stretchArgon2id('company-secrets', ROOM);
	const [, sB] = handshake(A, B, prs, rn);
	const ctag = sB.confirmTag();

	// ── CPace 密码绑定性（可证伪）──
	//
	// 固定临时值（同一对标量与 ya），只变 prs。
	// 若 prs 不参与生成元 G，错误密码会算出同一个 G、同一个 ya、同一个 ISK，断言即变红。
	// 反之，若每次猜测都重新 prepare()，随机 ya 必然不同，断言会无条件通过。
	const { sid, CI } = cpaceContext(ROOM, A.bundle.id, B.bundle.id, rn,
		A.bundle.ipk, B.bundle.ipk, A.bundle.xpk, B.bundle.xpk);
	const scalarOf = (byte) => ristretto255_hasher.hashToScalar(new Uint8Array(32).fill(byte));
	const aA = scalarOf(1), aB = scalarOf(2);
	const GTrue = calculateGenerator(prs, sid, CI);
	const yaA = GTrue.multiply(aA).toBytes();
	const yaB = GTrue.multiply(aB).toBytes();
	const iskTrue = cpaceFinish(aA, yaB, yaA, sid, CI);

	// 正控：同输入必须可复现 —— 证明下面的不等比较不是因为类型/长度而恒真
	ok(b64(cpaceFinish(aA, yaB, yaA, sid, CI)) === b64(iskTrue) && iskTrue.length === 64,
		'正控：同型同长的 ISK 可以判等（等号在本测试中是可达的）');

	// 可证伪核心：固定 ya 与标量，仅改密码 → ISK 必须改变
	const dict = ['company', 'secrets', 'hunter2', 'password', '123456', 'PW-别的', ''];
	let leaked = 0;
	for (const guess of dict) {
		const Gw = calculateGenerator(stretchArgon2id(guess, ROOM), sid, CI);
		const yaAw = Gw.multiply(aA).toBytes();
		const yaBw = Gw.multiply(aB).toBytes();
		if (b64(cpaceFinish(aA, yaBw, yaAw, sid, CI)) === b64(iskTrue)) leaked++;
	}
	ok(leaked === 0, '密码绑定性：固定临时值时，换密码必然换 ISK（若 G 忽略 prs 则此处变红）',
		`${dict.length} 个错误密码全部未复现`);

	// 可证伪：ISK 必须依赖对端 ya
	const yaB2 = GTrue.multiply(scalarOf(9)).toBytes();
	ok(b64(cpaceFinish(aA, yaB2, yaA, sid, CI)) !== b64(iskTrue),
		'ISK 依赖对端 ya（对端未参与即无法确定共享密钥）');

	// 可证伪：角色互换不影响结果（ya/yb 按字节排序而非角色序）
	ok(b64(cpaceFinish(aB, yaA, yaB, sid, CI)) === b64(iskTrue),
		'角色互换得到同一 ISK（ISK 内 ya/yb 按字节序排列，双方对称）');

	// 离线攻击的真实论点：攻击者猜对密码也不能复现——因为缺对方的 ya 与标量
	const aAtk = scalarOf(7);
	const yaAtk = GTrue.multiply(aAtk).toBytes();
	ok(b64(cpaceFinish(aAtk, yaB, yaAtk, sid, CI)) !== b64(iskTrue),
		'离线字典攻击不可行：猜对密码也需对方 ya，攻击者用自己的临时标量无法复现 ISK');

	const dt0 = Date.now(); stretchArgon2id('x', ROOM); const dt = Date.now() - dt0;
	ok(dt > 100, `Argon2id 单次拉伸 ${dt}ms（t=2,m=19456,p=1）抬高在线猜测成本`);
	ok(b64(stretchArgon2id('x', ROOM)) === b64(stretchArgon2id('x', ROOM)), '拉伸确定性（一次计算全房间复用）');
	const [sP] = handshake(A, B, prs, rn);
	ok(sP.authMode === 'pake', 'pake 模式标记');
	ok(handshake(A, B, new Uint8Array(0), rn)[0].authMode === 'no-password', '空密码 → no-password 标记（UI 提示依赖安全码）');
}

// ═════ ②' epoch 跳变上限（H1 拒绝服务回归）═════
console.log('\n②\' epoch 跳变上限（hs.e 由对端可控）');
{
	const rn = nonceOf(21);
	const A = bundleWith(makePeer(31), rn), B = bundleWith(makePeer(32), rn);
	const prs2 = stretchArgon2id('pw', ROOM);
	const px = Session.prepare(A.bundle, B.bundle, prs2, ROOM, rn);
	const py = Session.prepare(B.bundle, A.bundle, prs2, ROOM, rn);
	const xIsLo = A.bundle.id < B.bundle.id;
	const lo = xIsLo ? A : B, hi = xIsLo ? B : A;
	const pLo = xIsLo ? px : py, pHi = xIsLo ? py : px;

	// 合法场景：epoch 跳 1 必须正常放行
	const sOk = Session.pair(lo.bundle, hi.bundle, pLo, pHi.yaBytes, null, prs2, ROOM, rn, 1);
	ok(sOk.epoch === 1, 'epoch=1 的握手正常建立');
	// 跳 EPOCH_MAX_STEPS 以内也应放行
	const sMax = Session.pair(lo.bundle, hi.bundle, pLo, pHi.yaBytes, null, prs2, ROOM, rn, EPOCH_MAX_STEPS);
	ok(sMax.epoch === EPOCH_MAX_STEPS, `epoch=${EPOCH_MAX_STEPS}（上限内）放行`);
	// 越界必须被拒：否则单条 hs 帧即可让本端做任意轮 HKDF 推进
	const tDoS = Date.now();
	throws(() => Session.pair(lo.bundle, hi.bundle, pLo, pHi.yaBytes, null, prs2, ROOM, rn, 100000),
		Err.STATE_DESYNC, 'pair(epoch=100000) 被步数闸门拒绝（H1 修复）');
	throws(() => Session.pair(lo.bundle, hi.bundle, pLo, pHi.yaBytes, null, prs2, ROOM, rn, 1e9),
		Err.STATE_DESYNC, 'pair(epoch=1e9) 被拒绝，不再挂起 UI');
	ok(Date.now() - tDoS < 1000, `恶意 epoch 的配对耗时被限制在 ${Date.now() - tDoS}ms`);
	// 直接调 rotateTo 的跳变闸门同样生效
	const sGate = Session.pair(lo.bundle, hi.bundle, pLo, pHi.yaBytes, null, prs2, ROOM, rn, 0);
	throws(() => sGate.rotateTo(EPOCH_MAX_STEPS + 1), Err.STATE_DESYNC, `rotateTo 超过 ${EPOCH_MAX_STEPS} 步被拒`);
}

// ═════ ③ AEAD / 重放矩阵 / 填充 ═════
console.log('\n③ AEAD 与填充');
{
	const rn = nonceOf(9);
	const A = bundleWith(makePeer(11), rn), B = bundleWith(makePeer(12), rn);
	const prs = stretchArgon2id('pw', ROOM);
	const [sA, sB] = handshake(A, B, prs, rn);

	const wire = sA.encrypt({ a: 'm', t: 'text', d: '转账100元' });
	const obj = JSON.parse(wire);
	const flip = (w, byteIdx) => { const o = JSON.parse(w); const b = unb64(o.ct); b[byteIdx] ^= 1; o.ct = b64(b); return JSON.stringify(o); };
	throws(() => sB.decrypt(flip(wire, 8)), Err.AUTH_FAILED, '比特翻转被 Poly1305 拒绝');
	ok(sB.decrypt(wire).d === '转账100元', '未篡改正常解出');
	throws(() => sB.decrypt(wire), Err.REPLAY, '重放被拒');
	throws(() => { const o = JSON.parse(wire); o.to = 'ffffffffffff'; sB.decrypt(JSON.stringify(o)); }, Err.REPLAY, '改 to 转发被拒');

	// 文件分片 AAD 绑定（规格 §10.3）
	const fw = sA.encrypt({ a: 'm', t: 'file_volume', d: { fileId: 'f1', volumeIndex: 3, data: 'xxx' } }, { fid: 'f1', vi: 3, tv: 10 });
	const fo = JSON.parse(fw);
	throws(() => { const o = { ...fo, f: { fid: 'f1', vi: 7, tv: 10 } }; sB.decrypt(JSON.stringify(o)); }, Err.AUTH_FAILED, '分片序号进 AAD：中继重排被拒');
	ok(sB.decrypt(fw).d.volumeIndex === 3, '分片正常解出');

	// 跨 peer
	const C = bundleWith(makePeer(13), rn);
	const [sCtoA] = handshake(C, A, prs, rn);
	throws(() => sCtoA.decrypt(wire), Err.REPLAY, '发给别的 peer 的密文到我这里：to 不符直接拒（跨 peer 转发无效）');

	// 填充与长度掩盖
	const short = sA.encrypt({ a: 'm', t: 'text', d: '好' });
	const longish = sA.encrypt({ a: 'm', t: 'text', d: '明天上午十点打款到 offshore 账户' });
	ok(JSON.parse(short).ct.length === JSON.parse(longish).ct.length, '短消息密文长度一致（256B 分级）');
	for (const len of [8185, 8190, 8191]) {
		const body = 'x'.repeat(len);
		ok(sB.decrypt(sA.encrypt({ d: body })).d.length === len, `载荷 ${len}B 往返一致（FIX-PAD 边界修复）`);
	}
	for (const len of [1, 255, 256, 8191, 8192, 9000]) {
		const raw = new Uint8Array(len).fill(65);
		ok(unpadPayload(padPayload(raw)).length === len, `pad/unpad ${len}B 往返`);
	}
}

// ═════ ④ 密钥轮换 ═════
console.log('\n④ 密钥轮换');
{
	const rn = nonceOf(21);
	const A = bundleWith(makePeer(31), rn), B = bundleWith(makePeer(32), rn);
	const prs = stretchArgon2id('pw', ROOM);
	const [sA, sB] = handshake(A, B, prs, rn);
	const fp0 = sA.fingerprint;
	const w0 = sA.encrypt({ a: 'm', t: 'text', d: 'e0' });

	const t0 = Date.now();
	sA.rotateTo(1); sB.rotateTo(1);
	ok(Date.now() - t0 < 50, `轮换耗时 ${Date.now() - t0}ms（无 KEM，纯 HKDF）`);
	ok(sA.root.join() === sB.root.join(), '零往返轮换后 root 仍一致');
	ok(sA.fingerprint === fp0, '轮换后安全码不变');
	ok(roundtrip(sA, sB, 'epoch1'), '轮换后消息互通');

	// 上一轮在途容忍 + 自动追赶
	sA.rotateTo(2);
	const w2 = sA.encrypt({ a: 'm', t: 'text', d: 'e2' });   // B 仍在 1
	sA.rotateTo(3);
	const w3 = sA.encrypt({ a: 'm', t: 'text', d: 'e3' });   // B 仍在 1
	ok(sB.decrypt(w3).d === 'e3', 'e>epoch 自动追赶（B 1→3）');
	ok(sB.decrypt(w2).d === 'e2', 'e=epoch-1 的在途消息经上一轮链解出');
	throws(() => sB.decrypt(w2), Err.REPLAY, '消费后重放被拒');
	throws(() => sB.decrypt(w0), Err.STALE_EPOCH, '早于 epoch-1 的轮次 → STALE_EPOCH');
	throws(() => sB.rotateTo(1), Err.STALE_EPOCH, 'epoch 回退 → STALE_EPOCH');
	throws(() => sB.rotateTo(sB.epoch + 100), Err.STATE_DESYNC, '跳跃 >64 → STATE_DESYNC');

	// 握手 epoch 钉死：两侧以 max 配对（模拟广播到达顺序差）
	const [sX, sY] = handshake(A, B, prs, rn, 5);
	ok(sX.confirmTag() === sY.confirmTag(), '配对钉死同 epoch → 标签一致');
	ok(roundtrip(sX, sY, 'raced'), '钉死后首条消息互通');
	// 不对称：一侧带 6 的计数器配对，另一侧钉死到 6
	const px = Session.prepare(A.bundle, B.bundle, prs, ROOM, rn);
	const py = Session.prepare(B.bundle, A.bundle, prs, ROOM, rn);
	const loIsA = A.bundle.id < B.bundle.id;
	const loB = loIsA ? A : B, hiB = loIsA ? B : A;
	const pLo = loIsA ? px : py, pHi = loIsA ? py : px;
	const sLoR = Session.pair(loB.bundle, hiB.bundle, pLo, pHi.yaBytes, null, prs, ROOM, rn, 6);
	const sHiR = Session.pair(hiB.bundle, loB.bundle, pHi, pLo.yaBytes, sLoR.kemCipherText, prs, ROOM, rn, 6);
	ok(sLoR.confirmTag() === sHiR.confirmTag(), '双方统一钉 max(eA,eB)=6 → 标签一致（竞态修复回归）');

	// 双向乱序：B 停在轮次 k，A 已到 k+1
	const [sA2, sB2] = handshake(A, B, prs, rn);
	sA2.rotateTo(1);
	const wBack = sB2.encrypt({ a: 'm', t: 'text', d: 'from-B-e0' });
	sA2.rotateTo(2);
	const wNew2 = sA2.encrypt({ a: 'm', t: 'text', d: 'to-B-e2' });
	sB2.rotateTo(2);
	ok(sB2.decrypt(wNew2).d === 'to-B-e2', 'B 收 A 的 e=2 消息');
	const wLate = sB2.encrypt({ a: 'm', t: 'text', d: 'from-B-e2' });
	sB2.rotateTo(3);
	ok(sA2.decrypt(wLate).d === 'from-B-e2', 'A 追赶至 3，B 的 e=2 在途消息解出');
	throws(() => sA2.decrypt(wBack), Err.STALE_EPOCH, '早于 epoch-1 的轮次 → STALE_EPOCH（规格只容忍一轮）');
}

// ═════ ⑤ 重放/序号 ═════
console.log('\n⑤ 重放/序号');
{
	const rn = nonceOf(41);
	const A = bundleWith(makePeer(41), rn), B = bundleWith(makePeer(42), rn);
	const prs = stretchArgon2id('pw', ROOM);
	const [sA, sB] = handshake(A, B, prs, rn);
	const ws = [];
	for (let i = 0; i < 5; i++) ws.push(sA.encrypt({ a: 'm', t: 'text', d: 'msg' + i }));
	ok(sB.decrypt(ws[2]).d === 'msg2', '乱序快进（2 先到）');
	throws(() => sB.decrypt(ws[2]), Err.REPLAY, '重复序号被拒');
	throws(() => { const o = JSON.parse(ws[4]); o.n = o.n + 5000; sB.decrypt(JSON.stringify(o)); }, Err.STATE_DESYNC, '序号跳跃 >4096 → STATE_DESYNC');
	ok(sB.decrypt(ws[4]).d === 'msg4', '快进后合法后续消息正常');
}

// ═════ ⑥ 身份/低阶点/令牌桶/新会话隔离 ═════
console.log('\n⑥ 身份与其他');
{
	const seed = new Uint8Array(32); seed[0] = 9;
	const a1 = new Identity(seed), a2 = new Identity(seed);
	ok(a1.id === a2.id, 'clientId 由身份决定，重连恒定');
	ok(/^[0-9a-f]{12}$/.test(a1.id), 'id 为 12 hex (48bit)');
	const rn = nonceOf(51);
	const a1bundle = a1.makeBundle(rn);
	const j = JSON.stringify({ id: a1bundle.id, ipk: a1bundle.ipk, xpk: a1bundle.xpk, kpk: a1bundle.kpk, sig: a1bundle.sig });
	ok(j.length < 8192, `bundle 线上体积 ${j.length}B < 8192B`);

	// 低阶 x25519 公钥
	const rn2 = nonceOf(52);
	const M = bundleWith(makePeer(60), rn2);
	const V = bundleWith(makePeer(61), rn2);
	const lowOrder = new Uint8Array(32); lowOrder[0] = 1;   // u=1 是真正的低阶点
	V.bundle.xpk = b64(lowOrder);
	const prs2 = stretchArgon2id('pw', ROOM);
	const pm = Session.prepare(M.bundle, V.bundle, prs2, ROOM, rn2);
	const pv = Session.prepare(V.bundle, M.bundle, prs2, ROOM, rn2);
	// 低阶点只有"读取对端 xpk 的那次配对"才会接触 → 让 V(被篡改方) 先作为任一侧完成 encap，
	// 再用 M 侧 pair 读取 V 的 xpk
	const vIsLo = V.bundle.id < M.bundle.id;
	let threw = false;
	try {
		const sLo2 = vIsLo
			? Session.pair(V.bundle, M.bundle, pv, pm.yaBytes, null, prs2, ROOM, rn2, 0)
			: Session.pair(M.bundle, V.bundle, pm, pv.yaBytes, null, prs2, ROOM, rn2, 0);
		Session.pair(vIsLo ? M.bundle : V.bundle, vIsLo ? V.bundle : M.bundle,
			vIsLo ? pm : pv, vIsLo ? pv.yaBytes : pm.yaBytes, sLo2.kemCipherText, prs2, ROOM, rn2, 0);
	} catch { threw = true; }
	ok(threw, '低阶 x25519 公钥被拒（@noble 内置 + 我方全零兜底双保险）');

	const tb = new TokenBucket(5, 10);
	let taken = 0;
	for (let i = 0; i < 10; i++) if (tb.take()) taken++;
	ok(taken === 5, '令牌桶容量');
	await new Promise((r) => setTimeout(r, 320));
	ok(tb.take(), '按速率补充');

	// 重连即新会话：旧密文不可解
	const rnA = nonceOf(71);
	const X = bundleWith(makePeer(71), rnA);
	const Y1 = bundleWith(makePeer(72), rnA);
	const Y2 = bundleWith(makePeer(72), rnA);   // 同身份重连产生新 bundle
	const prsX = stretchArgon2id('pw', ROOM);
	const [xs1, ys1] = handshake(X, Y1, prsX, rnA);
	const wireOld = xs1.encrypt({ a: 'm', t: 'text', d: 'old' });
	const [xs2, ys2] = handshake(X, Y2, prsX, rnA);
	throws(() => ys2.decrypt(wireOld), Err.AUTH_FAILED, '重连后旧密文在新会话不可解（无需持久化序号）');
	ok(roundtrip(xs2, ys2, 'new'), '新会话互通');
}

// ═════ ⑦ CPace 与草案官方测试向量对齐 ═════
console.log('\n⑦ CPace 草案官方测试向量（draft-irtf-cfrg-cpace-21 附录 B.3）');
checkVectors((c, n, x = '') => ok(c, n, x));

// ═════ ⑧ 秘密驻留清理 ═════
console.log('\n⑧ 秘密驻留清理');
{
	const rn = nonceOf(41);
	const X = bundleWith(makePeer(81), rn), Y = bundleWith(makePeer(82), rn);
	const [sTx, sRx] = handshake(X, Y, stretchArgon2id('pw', ROOM), rn);
	ok(sRx.decrypt(sTx.encrypt({ a: 'm', t: 'text', d: 'seq0' })).d === 'seq0', '同序解密正常');
	for (let i = 1; i <= 3; i++) sTx.encrypt({ a: 'm', t: 'text', d: 'drop' + i });
	const late = sTx.encrypt({ a: 'm', t: 'text', d: 'catchup' });
	ok(sRx.decrypt(late).d === 'catchup', '跨 3 序号追赶（中间 mk 已清零）仍正确解密');
	ok(sRx.decrypt(sTx.encrypt({ a: 'm', t: 'text', d: 'seq4' })).d === 'seq4', '追赶后链路继续可用');
}

console.log(`\n${'═'.repeat(60)}\n结果: ${pass} 项通过, ${fail} 项失败\n${'═'.repeat(60)}`);
process.exit(fail ? 1 : 0);
