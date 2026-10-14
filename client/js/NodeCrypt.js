// ZQ-Chat v2 —— 端到端加密客户端
//
// 实现《ZQ-Chat-加密协议规格-v2》：X25519+ML-KEM-768 混合握手、
// CPace 风格 PAKE、XChaCha20-Poly1305+AAD、消息密钥链、epoch 密钥轮换。
// 公共接口与 v1 保持同形状（channel[id].shared 运行时类型从 Uint8Array
// 变为 Session），应用层仅按规格改动 2 处。
//
// 浏览器与 Node（headless 通道）双环境运行。

import { Identity, Session, Err, b64, unb64, stretchArgon2id, ARGON2_PARAMS, ROOM_NONCE_LEN } from './zqcrypto.mjs';
import { sha256 } from '@noble/hashes/sha2.js';

const ID_STORAGE_KEY = '***';
const enc = (s) => (typeof s === 'string' ? new TextEncoder().encode(s) : s);
const randomBytesBrowser = (n) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
const shaHex = (str) => Array.from(sha256(enc(str)), (b) => b.toString(16).padStart(2, '0')).join('');

class NodeCrypt {
	constructor(config = {}, callbacks = {}) {
		this.config = {
			wsAddress: config.wsAddress || '',
			wsFactory: config.wsFactory || null,             // 测试/代理环境注入连接构造器
			debug: config.debug || false,                 // 只打元数据，绝不打载荷
			pingInterval: config.pingInterval || 20000,
			reconnectBase: config.reconnectBase || 1000,   // 修复 v1 固定 3s：指数退避
			reconnectMax: config.reconnectMax || 30000,
			storage: config.storage || (typeof localStorage !== 'undefined' ? localStorage : null),
			forceSyncArgon: config.forceSyncArgon || false,
		};
		this.callbacks = {
			onServerClosed: callbacks.onServerClosed || null,
			onServerSecured: callbacks.onServerSecured || null,
			onClientSecured: callbacks.onClientSecured || null,
			onClientList: callbacks.onClientList || null,
			onClientMessage: callbacks.onClientMessage || null,
			onClientLeft: callbacks.onClientLeft || null,
			onPeerError: callbacks.onPeerError || null,     // v2 新增：密码错误/会话失效的明确信号
			onRoomError: callbacks.onRoomError || null,     // v2 新增：房间级错误（重复 id 等）
		};
		this.identity = this._loadOrCreateIdentity();
		this.credentials = null;
		this._prsCache = null;      // { channel, prs, authMode }，首次拉伸后复用
		this.connection = null;
		this.serverShared = null;      // 真值标记：已加入房间（兼容 v1 应用层判空）
		this.roomNonce = null;         // Uint8Array(16)
		this.epoch = 0;
		this.prs = null;               // Argon2id 拉伸结果
		this.channel = {};             // peerId -> { username, keys:bundle, shared:Session, prep, state }
		this.wsUrl = '';
		this.reconnectTimer = null;
		this.reconnectAttempt = 0;
		this.fatalClose = false;       // 不再重连的关闭
		this.ping = null;
		this.closing = false;
		this._argonReq = 0;
		this._argonWaiters = new Map();
		this._argonWorker = null;
		this._joinRetried = false;
	}

	// ═══════════════ 身份持久化 ═══════════════
	_loadOrCreateIdentity() {
		let seed = null;
		try {
			if (this.config.storage) seed = this.config.storage.getItem(ID_STORAGE_KEY);
		} catch { /* ignore */ }
		const id = new Identity(seed ? unb64(seed) : null);
		if (!seed) {
			try { if (this.config.storage) this.config.storage.setItem(ID_STORAGE_KEY, id.seedB64); } catch { /* ignore */ }
			this.logEvent('identity', 'created ' + id.id);
		} else {
			this.logEvent('identity', 'restored ' + id.id);
		}
		return id;
	}

	// ═══════════════ Argon2id（Web Worker 优先，失败回退同步）═══════════════
	_getArgonWorker() {
		if (this._argonWorker !== null) return this._argonWorker;
		if (this.config.forceSyncArgon || typeof Worker === 'undefined') { this._argonWorker = false; return false; }
		try {
			const w = new Worker(new URL('./argon.worker.js', import.meta.url), { type: 'module' });
			w.onmessage = (ev) => {
				const { id, ok, prs, error } = ev.data;
				const res = this._argonWaiters.get(id);
				if (!res) return;
				this._argonWaiters.delete(id);
				ok ? res.ok(prs) : res.err(new Error(error));
			};
			w.onerror = (e) => {
				for (const [, res] of this._argonWaiters) res.err(new Error(String(e && e.message || 'worker error')));
				this._argonWaiters.clear();
				this._argonWorker = false;   // 回退同步路径
			};
			this._argonWorker = w;
			return w;
		} catch { this._argonWorker = false; return false; }
	}

	async _stretch(password, roomId) {
		if (password === undefined || password === null || password === '') {
			return { prs: new Uint8Array(0), authMode: 'no-password' };
		}
		const w = this._getArgonWorker();
		if (w) {
			try {
				const prs = await Promise.race([
					new Promise((ok, err) => {
						const id = ++this._argonReq;
						this._argonWaiters.set(id, { ok, err });
						w.postMessage({ id, password, roomId, params: ARGON2_PARAMS });
					}),
					new Promise((_, rej) => setTimeout(() => rej(new Error('worker-timeout')), 8000)),
				]);
				return { prs: new Uint8Array(prs), authMode: 'pake' };
			} catch (e) { this.logEvent('argon-worker-fallback', String(e.message || e), 'warn'); }
		}
		return { prs: stretchArgon2id(password, roomId), authMode: 'pake' };
	}

	// ═══════════════ 凭证与连接（与 v1 同签名）═══════════════
	setCredentials(username, channel, password) {
		this.logEvent('setCredentials');
		try {
			this.credentials = { username, channel: shaHex(channel), password };
			this._prsCache = null;
			this.wsUrl = `${this.config.wsAddress.replace(/\/$/, '')}/chat?r=${encodeURIComponent(this.credentials.channel)}`;
		} catch (error) {
			this.logEvent('setCredentials', error, 'error');
			return false;
		}
		return true;
	}

	connect() {
		if (!this.credentials) return false;
		this.logEvent('connect', this.wsUrl);
		this._stopReconnect();
		this._stopPing();
		this.serverShared = null;
		this.channel = {};
		this.fatalClose = false;
		this.closing = false;
		try {
			const WS = this.config.wsFactory || globalThis.WebSocket;
			this.connection = new WS(this.wsUrl);
			this.connection.onopen = () => this.onOpen();
			this.connection.onmessage = (e) => this.onMessage(e);
			this.connection.onerror = (e) => this.onError(e);
			this.connection.onclose = (e) => this.onClose(e);
		} catch (error) {
			this.logEvent('connect', error, 'error');
			return false;
		}
		return true;
	}

	destruct() {
		this.logEvent('destruct');
		this._stopReconnect();
		this._stopPing();
		this.closing = true;
		if (this._argonWorker) { try { this._argonWorker.terminate(); } catch { /* ignore */ } this._argonWorker = null; }
		try { if (this.connection) { this.connection.onclose = null; this.connection.close(); } } catch { /* ignore */ }
		this.connection = null;
		this.channel = {};
		this.serverShared = null;
		this.credentials = null;
		this.prs = null;
		this._prsCache = null;
		this._wipeBundle();
		return true;
	}

	// 退出房间时清零会话临时密钥
	_wipeBundle() {
		const b = this.bundle;
		if (!b) return;
		for (const k of ['_xsk', '_ksk']) {
			if (b[k] instanceof Uint8Array) b[k].fill(0);
		}
		this.bundle = null;
	}

	disconnect() {
		this._stopReconnect();
		this._stopPing();
		this.closing = true;
		try { if (this.connection && this.connection.readyState === 1) this.connection.close(); } catch { /* ignore */ }
	}

	async onOpen() {
		this.logEvent('onOpen', `readyState=${this.connection && this.connection.readyState} wsUrl=${this.wsUrl.slice(-8)}`);
		this.reconnectAttempt = 0;
		this._startPing();
		this._send({ t: 'nonce' });
	}

	// ═══════════════ 服务端消息分发 ═══════════════
	async onMessage(event) {
		if (!this.isString(event.data)) return;
		if (event.data === 'pong') return;
		let msg;
		try { msg = JSON.parse(event.data); } catch { this.logEvent('malformed-frame', 'non-json', 'warn'); return; }
		if (!msg || !this.isString(msg.t)) return;
		try {
			switch (msg.t) {
				case 'nonce': await this._onNonce(msg); break;
				case 'joined': await this._onJoined(msg); break;
				case 'member.add': await this._onMemberAdd(msg); break;
				case 'member.gone': this._onMemberGone(msg); break;
				case 'epoch': this._onEpoch(msg); break;
				case 'hs': await this._onHs(msg); break;
				case 'ctag': this._onCtag(msg); break;
				case 'hsreq': this._onHsReq(msg); break;
				case 'msg': this._onMsg(msg); break;
				case 'error': this._onServerError(msg); break;
				default: /* 前向兼容：忽略未知类型 */ break;
			}
		} catch (e) {
			// 规格 §7.5：单条恶意消息不得打断消息循环
			this.logEvent('dispatch-error', `${msg.t}: ${e.code || ''}${e.message || ''}`, 'warn');
		}
	}

	// —— 握手序列 ——
	async _onNonce(msg) {
		this.epoch = msg.epoch >>> 0;
		this.roomNonce = msg.nonce ? unb64(msg.nonce) : randomBytesBrowser(ROOM_NONCE_LEN);
		if (!msg.nonce) this.logEvent('room', 'adopting our own roomNonce (first member)');
		// prs = Argon2id(密码, 房间名哈希)，只与凭据绑定、与连接无关：
		// 首次拉伸后缓存并抹除原文，重连复用缓存（否则重连就又需要密码原文了）。
		if (!this._prsCache || this._prsCache.channel !== this.credentials.channel) {
			const { prs, authMode } = await this._stretch(this.credentials.password, this.credentials.channel);
			this._prsCache = { channel: this.credentials.channel, prs, authMode };
			if (this.credentials.password !== undefined) this.credentials.password = null;
		}
		const { prs, authMode } = this._prsCache;
		this.prs = prs; this.authMode = authMode;
		this.bundle = this.identity.makeBundle(this.roomNonce);
		this._send({ t: 'join', bundle: this._publicBundle(this.bundle), nonce: b64(this.roomNonce) });
	}

	_publicBundle(b) { return { id: b.id, ipk: b.ipk, xpk: b.xpk, kpk: b.kpk, sig: b.sig }; }

	_onServerError(msg) {
		if (msg.code === 'NONCE_CONFLICT' && msg.nonce && !this._joinRetried) {
			// 两名"首成员"并发创建房间：采用服务器权威 nonce，重签名重发（一次）
			this._joinRetried = true;
			this.roomNonce = unb64(msg.nonce);
			this.bundle = this.identity.makeBundle(this.roomNonce);
			this._send({ t: 'join', bundle: this._publicBundle(this.bundle), nonce: b64(this.roomNonce) });
			return;
		}
		this.logEvent('server-error', msg.code || '?', 'error');
		if (msg.code === 'DUPLICATE_ID') {
			this.fatalClose = true;
			this._cb('onRoomError', { code: 'DUPLICATE_ID', hint: '同一身份已在该房间（其他标签页？)' });
		}
	}

	async _onJoined(msg) {
		this.serverShared = { relay: true };            // 真值标记，兼容 v1 应用层
		this.epoch = (msg.epoch ?? this.epoch) >>> 0;
		this._cb('onServerSecured');
		if (msg.noPasswordWarn) this._cb('onRoomError', { code: 'NO_PASSWORD_ROOM' });
		for (const bundle of (msg.members || [])) await this._addPeer(bundle);
		this._emitClientList();
	}

	async _onMemberAdd(msg) {
		if (msg.epoch > this.epoch) { this._rotateAll(msg.epoch); }
		this.epoch = Math.max(this.epoch, (msg.epoch ?? this.epoch) >>> 0);
		await this._addPeer(msg.bundle);
		this._emitClientList();
	}

	_onMemberGone(msg) {
		if (msg.epoch > this.epoch) this._rotateAll(msg.epoch);
		this.epoch = Math.max(this.epoch, (msg.epoch ?? this.epoch) >>> 0);
		// 房间计数器由随后的 {t:'epoch'} 广播统一推进（此处不重复 rotate）
		const id = msg.id;
		if (id !== this.identity.id && this.channel[id]) {
			delete this.channel[id];
			this._cb('onClientLeft', { clientId: id });
			this._emitClientList();
		}
	}

	_onEpoch(msg) {
		this.epoch = Math.max(this.epoch, msg.e >>> 0);
		this._rotateAll(msg.e >>> 0);
	}

	_rotateAll(newEpoch) {
		for (const id in this.channel) {
			const peer = this.channel[id];
			if (peer.shared) {
				try { peer.shared.rotateTo(newEpoch); }
				catch (e) {
					if (e.code === Err.STATE_DESYNC) { this.logEvent('rotate-desync', id, 'warn'); this._send({ t: 'hsreq', to: id }); peer.shared = null; peer.state = 'resync'; }
					else this.logEvent('rotate-error', `${id}:${e.code}`, 'warn');
				}
			}
		}
	}

	// —— 对端管理（握手状态机）——
	// 流程：双方各自发 hs{ya}；封装方(id 较小)收到对端 ya 后完成 pair，
	// 重发 hs{ya,kemCt} 并附 ctag；解封方收到 kemCt 后 pair 并发 ctag。
	async _addPeer(bundle) {
		if (!bundle || bundle.id === this.identity.id) return;
		if (!Identity.verifyBundle(bundle, this.roomNonce)) {
			this.logEvent('bad-bundle', bundle.id, 'warn');       // 丢弃未认证密钥包
			this._cb('onPeerError', { clientId: bundle.id, code: Err.BAD_BUNDLE });
			return;
		}
		let peer = this.channel[bundle.id];
		if (peer && peer.shared) { peer.bundle = bundle; return; } // 会话仍在：仅更新缓存
		if (!peer) peer = { username: null, keys: bundle, shared: null, prep: null, state: 'init' };
		peer.bundle = bundle;
		this.channel[bundle.id] = peer;
		peer.prep = Session.prepare(this.bundle, bundle, this.prs, this.credentials.channel, this.roomNonce);
		peer.state = 'prepped';
		this._sendHs(bundle.id, null);                              // ya-only
		this._replayPendingHs(bundle.id);
	}

	_replayPendingHs(peerId) {
		const q = this._pendingHs && this._pendingHs[peerId];
		if (!q || q.length === 0) return;
		delete this._pendingHs[peerId];
		if (!this.channel[peerId]) return;
		for (const m of q) { try { this._onHs(m); } catch { /* ignore */ } }
	}

	_sendHs(peerId, kemCtBytes) {
		const peer = this.channel[peerId];
		if (!peer || !peer.prep) return;
		const yaB64 = b64(peer.prep.yaBytes);
		peer.myHsEpoch = this.epoch;   // 钉死配对轮次 = max(我方 hs.e, 对端 hs.e)，本地计数器不参与（消除两侧不对称竞态）
		const sig = this.identity.signHS(peerId, this.roomNonce, peer.prep.yaBytes, kemCtBytes, this.epoch);
		this._send({ t: 'hs', to: peerId, ya: yaB64, kemCt: kemCtBytes ? b64(kemCtBytes) : null, e: this.epoch, sig });
	}

	_onHs(msg) {
		const peer = this.channel[msg.from];
		if (!peer || !peer.bundle) {
			// 竞态：hs 可能先于 member.add 到达（服务端异步验签窗口）。
			// 暂存 5 秒，peer 就位后重放，避免握手死锁。
			this._pendingHs = this._pendingHs || {};
			(this._pendingHs[msg.from] ||= []).push(msg);
			setTimeout(() => { this._replayPendingHs(msg.from); }, 5000);
			return;
		}
		let yaB = null, ctB = null;
		try { yaB = msg.ya ? unb64(msg.ya) : null; ctB = msg.kemCt ? unb64(msg.kemCt) : null; }
		catch { this.logEvent('hs-malformed', msg.from, 'warn'); return; }
		// e 参与签名，必须先校验取值范围再验签，否则验签用的 epoch 与实际采用的不一致
		if (!Number.isSafeInteger(msg.e) || msg.e < 0) {
			this.logEvent('hs-epoch-invalid', `${msg.from}:${msg.e}`, 'warn');
			return;
		}
		if (!Identity.verifyHSSig(unb64(peer.bundle.ipk), msg.sig, this.identity.id, this.roomNonce, yaB, ctB, msg.e)) {
			this.logEvent('hs-sig-fail', msg.from, 'warn');
			this._cb('onPeerError', { clientId: msg.from, code: Err.BAD_BUNDLE });
			return;
		}
		peer.peerYa = yaB;
		if (ctB) peer.peerKemCt = ctB;
		peer.peerEpoch = msg.e;
		if (peer.shared) return;                       // 已配对：忽略（resync 只经由 hsreq 显式重置）
		if (!peer.peerYa) return;
		const iAmEncap = this.identity.id < msg.from;
		// 握手 epoch 钉死：只取双方 hs 携带的 e 的 max（两侧看到的值相同 → 对称）。
		// 若本地房间计数器更高，配对完成后统一 rotateTo 追上（广播最终会让两侧一致）。
		const initEpoch = Math.max(peer.myHsEpoch || 0, peer.peerEpoch || 0);
		if (!peer.prep) peer.prep = Session.prepare(this.bundle, peer.bundle, this.prs, this.credentials.channel, this.roomNonce);
		try {
			if (iAmEncap) {
				peer.shared = Session.pair(this.bundle, peer.bundle, peer.prep, peer.peerYa, null, this.prs,
					this.credentials.channel, this.roomNonce, initEpoch);
				peer.state = 'paired';
				this._sendHs(msg.from, peer.shared.kemCipherText);   // 携带本次封装密文，解封方以此配对
				this._sendCtag(msg.from);
			} else {
				if (!peer.peerKemCt) return;               // 等封装方的 kemCt
				peer.shared = Session.pair(this.bundle, peer.bundle, peer.prep, peer.peerYa, peer.peerKemCt, this.prs,
					this.credentials.channel, this.roomNonce, initEpoch);
				peer.state = 'paired';
				this._sendCtag(msg.from);
			}
		} catch (e) {
			this.logEvent('pair-fail', `${msg.from}:${e.code || e.message}`, 'warn');
			return;
		}
		// pair 已用完标量；yaBytes 是公开值，_sendHs 重发仍需
		if (typeof peer.prep.scalar === 'bigint') peer.prep.scalar = 0n;
	}

	_sendCtag(peerId) {
		const peer = this.channel[peerId];
		if (!peer || !peer.shared || peer.ctagSent) return;
		peer.ctagSent = true;
		this._send({ t: 'ctag', to: peerId, tag: peer.shared.confirmTag(), e: peer.shared.epoch });
	}

	_onCtag(msg) {
		const peer = this.channel[msg.from];
		if (!peer) return;
		if (!peer.shared) { this._sendHs(msg.from, null); return; }   // 对端抢先：重发我们的 hs
		if (!peer.shared.verifyConfirm(msg.tag)) {
			// 明确的密码错误信号（规格 §4.6/§9）
			this.logEvent('confirm-mismatch', msg.from, 'error');
			this._cb('onPeerError', { clientId: msg.from, code: Err.PASSWORD_MISMATCH });
			delete this.channel[msg.from];
			this._emitClientList();
			return;
		}
		peer.verified = true;
		if (!peer.usernameSent) {
			peer.usernameSent = true;
			this._send({ t: 'msg', to: [msg.from], c: [peer.shared.encrypt({ a: 'u', p: this.credentials.username })] });
		}
		this._emitClientList();
	}

	_onHsReq(msg) {
		const peer = this.channel[msg.from];
		if (!peer || !peer.bundle) return;
		peer.shared = null; peer.ctagSent = false; peer.encapCtB64 = null; peer.peerKemCt = null;
		peer.prep = Session.prepare(this.bundle, peer.bundle, this.prs, this.credentials.channel, this.roomNonce);
		this._sendHs(msg.from, null);
		this.logEvent('resync', msg.from);
	}

	// ═══════════════ 业务消息 ═══════════════
	_onMsg(msg) {
		const peer = this.channel[msg.from];
		if (!peer) return;
		if (!peer.shared || !this.isString(msg.c)) {
			this.logEvent('msg-unknown-peer', msg.from, 'warn');
			return;
		}
		let payload;
		try { payload = peer.shared.decrypt(msg.c); }
		catch (e) {
			this._handleDecryptError(peer, msg.from, e);
			return;
		}
		if (!this.isObject(payload) || !this.isString(payload.a)) return;
		if (payload.a === 'u' && this.isString(payload.p) && payload.p.match(/\S+/)) {
			if (!peer.username) {
				peer.username = payload.p.replace(/^\s+/, '').replace(/\s+$/, '');
				this._cb('onClientSecured', {
					clientId: msg.from,
					username: peer.username,
					fingerprint: peer.shared.fingerprint,
				});
			}
			this._emitClientList();
			return;
		}
		if (payload.a === 'm' && this.isString(payload.t) && (this.isString(payload.d) || this.isObject(payload.d))) {
			if (!peer.username) peer.username = 'Anonymous';
			this._cb('onClientMessage', {
				clientId: msg.from,
				username: peer.username,
				type: payload.t,
				data: payload.d,
			});
		}
	}

	_handleDecryptError(peer, from, e) {
		switch (e && e.code) {
			case Err.REPLAY:
			case Err.STALE_EPOCH:
				this.logEvent('drop', `${from}:${e.code}`, 'debug');       // 静默丢弃但可日志
				break;
			case Err.STATE_DESYNC:
				this.logEvent('desync', from, 'warn');
				this._send({ t: 'hsreq', to: from });
				peer.shared = null; peer.ctagSent = false;
				break;
			case Err.PASSWORD_MISMATCH:
				this._cb('onPeerError', { clientId: from, code: e.code });
				delete this.channel[from];
				this._emitClientList();
				break;
			default:
				this.logEvent('decrypt-fail', `${from}:${e.code || 'ERR'}`, 'warn');
				break;
		}
	}

	_emitClientList() {
		const clients = [];
		for (const clientId in this.channel) {
			const p = this.channel[clientId];
			// fingerprint 是会话密钥的派生物，UI 用它展示安全码供用户口头比对（检测 MITM）
			if (p.shared && p.username) {
				clients.push({ clientId, username: p.username, fingerprint: p.shared.fingerprint });
			}
		}
		this._cb('onClientList', clients, this.identity.id);
	}

	// ═══════════════ 发送 API（与 v1 同签名）═══════════════
	sendChannelMessage(type, data) {
		if (!this.serverShared) return false;
		try {
			const to = [], c = [];
			for (const clientId in this.channel) {
				const peer = this.channel[clientId];
				if (!peer.shared || !peer.username) continue;
				to.push(clientId);
				c.push(peer.shared.encrypt({ a: 'm', t: type, d: data }, fileAAD(type, data)));
			}
			if (to.length === 0) return false;
			return this._send({ t: 'msg', to, c });
		} catch (error) {
			this.logEvent('sendChannelMessage', error, 'error');
			return false;
		}
	}

	encryptClientMessage(message, session) {
		if (!session) return '';
		try { return session.encrypt(message, fileAAD(message && message.t, message && message.d)); }
		catch (e) { this.logEvent('encryptClientMessage', e.code || e.message, 'error'); return ''; }
	}

	decryptClientMessage(str, session) {
		try { return session.decrypt(str); }
		catch (e) { this.logEvent('decryptClientMessage', e.code || e.message, 'warn'); return {}; }
	}

	// 服务器信封为明文 JSON（服务器零密钥，无需加密）。key 参数仅为兼容旧签名保留，已忽略。
	encryptServerMessage(message, key) {
		try {
			if (message && message.a === 'c') {
				const wire = { t: 'msg', to: [message.c], c: [message.p] };
				const s = JSON.stringify(wire);
				return s.length > 8 * 1024 * 1024 ? '' : s;
			}
			if (message && message.a === 'w') {
				const ids = Object.keys(message.p || {});
				return JSON.stringify({ t: 'msg', to: ids, c: ids.map((i) => message.p[i]) });
			}
			return '';
		} catch (error) {
			this.logEvent('encryptServerMessage', error, 'error');
			return '';
		}
	}

	sendMessage(message) {
		return this._sendRaw(message);
	}

	isOpen() { return !!(this.connection && this.connection.readyState === 1); }
	isClosed() { return !this.connection || this.connection.readyState === 3; }

	// ═══════════════ 内部发送 ═══════════════
	_sendRaw(str) {
		try { if (this.isOpen()) { this.connection.send(str); return true; } }
		catch (e) { this.logEvent('sendMessage', e, 'error'); }
		return false;
	}
	_send(obj) { return this._sendRaw(JSON.stringify(obj)); }

	// ═══════════════ 心跳 / 重连（指数退避 + 抖动，规格 §8.4）═══════════════
	_startPing() {
		this._stopPing();
		this.ping = setInterval(() => { this._sendRaw('ping'); }, this.config.pingInterval);
	}
	_stopPing() { if (this.ping) { clearInterval(this.ping); this.ping = null; } }

	onError() { this.logEvent('onError', undefined, 'warn'); }

	onClose(event) {
		this.logEvent('onClose', `code=${event && event.code}`);
		this._stopPing();
		this.serverShared = null;
		if (this.credentials && !this.closing && !this.fatalClose) this._startReconnect();
		this._cb('onServerClosed');
	}

	_startReconnect() {
		this._stopReconnect();
		const base = Math.min(this.config.reconnectMax, this.config.reconnectBase * 2 ** this.reconnectAttempt);
		const delay = base + Math.floor(Math.random() * 500);
		this.reconnectAttempt++;
		this.logEvent('reconnect-in', `${delay}ms (attempt ${this.reconnectAttempt})`);
		this.reconnectTimer = setTimeout(() => { this.reconnectTimer = null; this.connect(); }, delay);
	}
	_stopReconnect() { if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; } }

	// ═══════════════ 工具 ═══════════════
	_cb(name, ...args) { const fn = this.callbacks[name]; if (!fn) return; try { fn(...args); } catch (e) { this.logEvent(name, e, 'error'); } }

	logEvent(source, message, level) {
		if (!this.config.debug) return;
		// v2 约定：message 只允许元数据（id / 错误码 / 延迟），载荷绝不进入日志
		const date = new Date();
		const p = (n) => String(n).padStart(2, '0');
		const ts = `${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())} ${p(date.getHours())}:${p(date.getMinutes())}:${p(date.getSeconds())}`;
		console.log(`[${ts}] ${level ? level.toUpperCase() : 'INFO'} ${source}${message !== undefined ? ': ' + message : ''}`);
	}

	isString(v) { return Object.prototype.toString.call(v) === '[object String]' && !!v; }
	isArray(v) { return Array.isArray(v); }
	isObject(v) { return v && Object.prototype.toString.call(v) === '[object Object]'; }
}

// 文件分片的 AAD 认证字段（规格 §10.3）：fileId + 分片序号 + 总片数
function fileAAD(type, data) {
	if (!type || !data || typeof type !== 'string') return null;
	if (!type.startsWith('file_')) return null;
	const o = {};
	if (data.fileId) o.fid = data.fileId;
	if (Number.isInteger(data.volumeIndex)) o.vi = data.volumeIndex;
	if (Number.isInteger(data.totalVolumes)) o.tv = data.totalVolumes;
	else if (Number.isInteger(data.volumes)) o.tv = data.volumes;
	return Object.keys(o).length ? o : null;
}

if (typeof window !== 'undefined') {
	window.NodeCrypt = NodeCrypt;
}
export default NodeCrypt;
export { NodeCrypt };
