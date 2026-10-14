# ZQ-Chat v2 API 调用文档

程序化调用方式。密码学内部见 [`spec-v2.md`](./spec-v2.md)，线上帧见 [`wire-v2.md`](./wire-v2.md)。

## 1. 模块入口

全部密码学基于 `@noble/*`，不依赖 WebCrypto，浏览器与 Node 双端一致。

```js
import NodeCrypt from './client/js/NodeCrypt.js';          // 主入口，同时挂载 window.NodeCrypt
import {
  Identity, Session, Err, CryptoError,
  b64, unb64, KDF, PROTO,
  padPayload, unpadPayload, PAD_BLOCK, PAD_MAX,
  stretchArgon2id, ARGON2_PARAMS,
  ROOM_NONCE_LEN, EPOCH_MAX_STEPS,
  TokenBucket,
} from './client/js/zqcrypto.mjs';
import {
  cpaceContext, cpaceInit, cpaceFinish,
  calculateGenerator, generatorString, sampleScalar, scalarMultVfy,
  prependLen, lvCat, oCat, transcriptIr, transcriptOc, DSI,
} from './client/js/zqcpace.mjs';
```

## 2. NodeCrypt

### 2.1 构造

```js
const nc = new NodeCrypt(config, callbacks);
```

`config`：

| 字段 | 默认 | 说明 |
|---|---|---|
| `wsAddress` | `''` | 中继基址，最终 URL 为 `${wsAddress}/chat?r=<roomId>` |
| `wsFactory` | `null` | 注入连接构造器 `(url) => WebSocketLike`，测试与代理环境用 |
| `debug` | `false` | 打开后向 console 输出**仅元数据**日志 |
| `pingInterval` | `20000` | 心跳间隔 ms |
| `reconnectBase` | `1000` | 重连退避基数 ms |
| `reconnectMax` | `30000` | 退避上限 ms |
| `storage` | `localStorage` | 需实现 `getItem` / `setItem`，用于持久化身份 seed |
| `forceSyncArgon` | `false` | 跳过 Web Worker，主线程同步跑 Argon2 |

`callbacks` 全部可选：

| 回调 | 签名 | 触发时机 |
|---|---|---|
| `onServerSecured` | `()` | 已加入房间 |
| `onServerClosed` | `()` | 连接关闭（含主动断开） |
| `onClientList` | `(clients, selfId)` | 成员列表变化 |
| `onClientSecured` | `({clientId, username, fingerprint})` | 与某 peer 完成密码确认 |
| `onClientMessage` | `({clientId, username, type, data})` | 收到业务消息 |
| `onClientLeft` | `({clientId})` | peer 离开 |
| `onPeerError` | `({clientId, code})` | 会话级错误，见 §2.4 |
| `onRoomError` | `({code, hint?})` | 房间级错误：`DUPLICATE_ID` / `NO_PASSWORD_ROOM` |

`clients` 元素：`{ clientId, username, fingerprint }`。

### 2.2 生命周期

```js
nc.setCredentials(username, roomName, password);  // 必须在 connect 之前
nc.connect();          // → false 表示未设置凭据
nc.disconnect();       // 主动断开，不自动重连
nc.destruct();         // 断开并清空全部状态（credentials / prs / channel）
```

重连采用指数退避 + 抖动。除 `DUPLICATE_ID` 外，异常关闭会自动重连；
`DUPLICATE_ID` 置 `fatalClose` 永不重连（同一身份已在该房间，需手动重进）。

### 2.3 发送

```js
nc.sendChannelMessage(type, data)   // → boolean，广播给全部已建立会话的 peer
nc.encryptClientMessage(msg, session)  // → 密文字符串
nc.decryptClientMessage(str, session)  // → 明文对象（失败返回 {}）
nc.encryptServerMessage(message, key)  // → 信封字符串；key 参数被忽略（v2 为明文信封）
nc.sendMessage(envelope)              // → boolean
nc.isOpen() / nc.isClosed()
```

私聊走单播信封：

```js
const peer = nc.channel[targetId];
const ct = nc.encryptClientMessage({ a:'m', t:'text_private', d:'你好' }, peer.shared);
const env = nc.encryptServerMessage({ a:'c', p: ct, c: targetId }, nc.serverShared);
nc.sendMessage(env);
```

### 2.4 错误信号

`onPeerError` 的 `code` 取值：`PASSWORD_MISMATCH`（密码不同，会话已丢弃，需重新加入）、
`BAD_BUNDLE`（密钥包或握手材料验签失败）、`STATE_DESYNC`（已自动请求对端重建会话）、
`AUTH_FAILED`、`REPLAY`、`STALE_EPOCH`、`MALFORMED`。

`onRoomError`：`DUPLICATE_ID`（同一身份已在房间）、`NO_PASSWORD_ROOM`（无密码房间，
此时 MITM 防护只剩安全码比对）。

### 2.5 公开属性

| 属性 | 说明 |
|---|---|
| `identity` | `Identity` 实例，`.id` 为 12 hex |
| `credentials` | `{username, channel, password}`；`password` 在首次拉伸后为 `null` |
| `channel` | `peerId → {username, bundle, shared, prep, state, verified, ctagSent, peerEpoch, …}`；`shared` 为 `Session` |
| `serverShared` | 已加入房间的真值标记 |
| `epoch` / `roomNonce` / `prs` / `authMode` | 当前房间会话参数 |

### 2.6 安全码

```js
const fp = nc.channel[peerId].shared.fingerprint;   // 60 hex
```

双方一致即可确认未被中间人替换会话。UI 侧见成员面板「安全码」按钮。

## 3. Identity

```js
const id = new Identity(seedOrNull);   // 省略或 null 则随机生成
id.id;          // 12 hex
id.pk;          // Ed25519 公钥 Uint8Array(32)
id.seedB64;     // 持久化用

id.makeBundle(roomNonceBytes);   // → {id, ipk, xpk, kpk, sig, _xsk, _ksk}，_ 前缀为本地秘密
Identity.verifyBundle(bundle, roomNonceBytes);   // → boolean

id.signHS(to, roomNonceBytes, yaBytes, kemCtBytes);           // → base64
Identity.verifyHSSig(ipk, sigB64, to, roomNonceBytes, yaBytes, kemCtBytes);  // → boolean
```

`makeBundle` **每次调用都生成新的** X25519 与 ML-KEM 临时密钥，对外只发 `_publicBundle()` 过滤后的部分。

## 4. Session

```js
const prep = Session.prepare(myBundle, peerBundle, prs, roomId, roomNonceBytes);
// → { yaBytes, scalar, G, sid, CI }

const s = Session.pair(myBundle, peerBundle, prep, peerYaBytes, kemCt,
                       prs, roomId, roomNonceBytes, epoch);
// kemCt：自己是封装方传 null，解封方传收到的密文
```

封装方固定为 id 较小一侧，错配抛 `MALFORMED`。

| 成员 | 说明 |
|---|---|
| `confirmTag()` | 本次握手的密码确认标签（base64, 16B） |
| `verifyConfirm(peerTag)` | 常数时间比较，不匹配返回 false |
| `fingerprint` | 安全码，60 hex |
| `authMode` | `'pake'` 或 `'no-password'` |
| `epoch` | 当前轮次 |
| `rotateTo(newEpoch, maxSteps = 64)` | 推进密钥链；越界抛 `STATE_DESYNC` |
| `encrypt(payload, aadExtra?)` | → 线上密文字符串 |
| `decrypt(wireStr)` | → 明文对象；失败抛 `CryptoError` |

`aadExtra` 用于文件分片：`{ fid, vi, tv }`。

## 5. 工具函数

```js
b64(u8) / unb64(str)          // 标准 base64（浏览器与 Node 通用）
KDF(ikm, salt, info, len=32)  // HKDF-SHA256
padPayload(bytes) / unpadPayload(p)
stretchArgon2id(password, roomId)
new TokenBucket(capacity, refillPerSec).take(n = 1)
```

常量：`PROTO='zqchat/v2'`、`ROOM_NONCE_LEN=16`、`EPOCH_MAX_STEPS=64`、
`PAD_BLOCK=256`、`PAD_MAX=8192`、`ARGON2_PARAMS={t:2,m:19456,p:1,dkLen:32}`。

## 6. 消息类型

`sendChannelMessage(type, data)` 与私聊的 `t` 取值：

| type | data 形状 |
|---|---|
| `text` / `text_private` | `string` |
| `image` / `image_private` | `{text?: string, images: string[]}`（data URL） |
| `file_start` | `{fileId, fileName, originalSize, compressedSize, totalVolumes, originalHash, archiveHash, fileCount, fileManifest, isArchive}` |
| `file_volume` | `{fileId, volumeIndex, volumeData}` |
| `file_complete` | `{fileId}` |

`file_*` 类型的载荷自动进入 AEAD 的 AAD（`{fid, vi, tv}`），防止分片被调包。

## 7. headless CLI

```bash
node headless/zqchat.mjs --url wss://host --room demo --pass pw --name alice \
     [--state ./alice.json] [--send "hi"] [--expect "hello"] \
     [--watch 15] [--mode interactive|one-shot] [--debug]
```

| 选项 | 说明 |
|---|---|
| `--url` | `wss://` 直连，或 `ws://127.0.0.1:18443` 经本地 ECH 桥 |
| `--room` | 房间名（内部取 sha256） |
| `--pass` | 房间密码；留空为无密码房间 |
| `--name` | 显示用户名，默认随机 |
| `--state` | 身份持久化文件，默认 `./.zqchat-<name>.json` |
| `--send` / `--expect` | 一次性模式：发送并等待指定文本 |
| `--watch` | 观察窗口秒数 |
| `--mode` | `interactive`（默认，stdin 逐行）/ `one-shot` |
| `--debug` | 协议日志写 stderr |

stdout 为逐行 JSON 事件：`start` / `secured` / `peer_ready` / `msg` / `msg_other` /
`sent` / `peers` / `id` / `codes` / `peer_left` / `peer_error` / `room_error` / `closed` / `expect`。

交互模式命令：`/quit`、`/peers`、`/id`、`/codes`（打印各 peer 安全码与 authMode）。

`--expect` 命中退出码 0，未命中 2。

## 8. 测试用 API

`tests/relay-harness.mjs` 在 Node 里运行真实 `worker/index.js`，用于端到端测试：

```js
import { createRelay, makeWsFactory, WSLink } from './tests/relay-harness.mjs';

const relay = createRelay();
const nc = new NodeCrypt({
  wsAddress: 'wss://relay.test',
  storage,                                   // 内存 localStorage 替身
  wsFactory: makeWsFactory(relay, roomHash), // 建立到内存中继的连接
}, callbacks);
```

`roomHash` 须与客户端一致：`hex(SHA256(房间名))`。同一 `storage` 复用同一身份。

```bash
node tests/crypto.test.mjs      # 密码学单元测试（90 项）
node tests/e2e-relay.test.mjs   # 真实中继 + 真实客户端端到端（34 项）
node tests/cpace-vectors.mjs    # CPace 草案官方测试向量（15 项）
node tests/live-e2e.mjs --url wss://host --room r --pass pw   # 打真实部署
```