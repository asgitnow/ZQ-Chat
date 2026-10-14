# ZQ-Chat v2 实现规格

本文描述 `client/js/zqcrypto.mjs`、`client/js/zqcpace.mjs`、`client/js/NodeCrypt.js` 与 `worker/index.js`
的实际实现。线上帧格式见 [`wire-v2.md`](./wire-v2.md)，程序调用方式见 [`api.md`](./api.md)。

## 1. 记号

`prepend_len(x)` = LEB128 变长长度前缀 ‖ x（CPace 草案 §6.3）。所有字节串默认 raw bytes，
线上传输为标准 base64（含 `+` `/` `=` 填充）。`‖` 表示字节串拼接。`hex` 小写。

## 2. 身份层

每个客户端持有长期 Ed25519 密钥对。

```
sk  = Ed25519 私钥（32B 随机，或从 storage 恢复）
pk  = Ed25519 公钥（32B）
id  = hex(SHA256(pk))[:12]          12 hex = 48 bit，重连后恒定
seedB64 = b64(sk)                  持久化用
```

私钥仅以 seed 形式存于 `storage`（浏览器 `localStorage`，headless 为 JSON 文件）。

## 3. 房间标识与 roomNonce

```
roomId   = hex(SHA256(房间名 UTF-8))        64 hex
roomNonce = 16B，由中继生成并在整个房间内一致
```

`roomId` 是全部 KDF 的 salt，同时进入 CPace 的 `sid`/`CI` 与消息 AAD 的 `room` 字段。

roomNonce 在房间清空（最后一名成员离开）时重置。新成员加入时若房间为空，由该成员提供自己的
roomNonce；并发首成员冲突时中继下发 `NONCE_CONFLICT`，客户端采用中继的权威值重签名重发一次。

## 4. bundle 与验签

加入房间时公布密钥包：

```
bundle = { id, ipk, xpk, kpk, sig }
  ipk = b64(Ed25519 公钥)      32B
  xpk = b64(X25519 公钥)       32B
  kpk = b64(ML-KEM-768 公钥)  1184B
  sig = Ed25519( id ‖ ipk ‖ xpk ‖ kpk ‖ roomNonce )
```

`sig` 覆盖全部公开材料与 roomNonce，因此 bundle 不能跨房间重放。中继在 `join` 时验签，
失败立即断开（close code 1008, `BAD_BUNDLE`）；客户端在 `_addPeer` 处二次验签，防止中继替换成员包。

`makeBundle()` 每次加入时生成**新的** X25519 与 ML-KEM 临时密钥对并本地保留（`_xsk`/`_ksk`），
`_publicBundle()` 只发公开部分。

## 5. 密码拉伸

```
prs = Argon2id( password, salt = roomId, { t:2, m:19456 KiB, p:1, dkLen:32 } )
```

- 空密码时 `prs = 空字节数组`，会话标记 `authMode = 'no-password'`，否则为 `'pake'`。
- 浏览器在 Web Worker（`argon.worker.js`）中计算，失败时回退主线程同步路径。
- 客户端只缓存 `prs`，首次拉伸后即抹除密码原文；重连复用缓存。

## 6. CPace PAKE（Ristretto255）

实现对齐 **draft-irtf-cfrg-cpace-21**，密码套件 **CPACE-RISTR255-SHA512**
（`G = G_Ristretto255`，`H = SHA-512`，草案 §8.3）。规范的字符串运算与群运算函数
（`prepend_len` / `lv_cat` / `o_cat` / `generator_string` / `calculate_generator` /
`sample_scalar` / `scalar_mult_vfy` / `transcript_ir` / `transcript_oc`）均按原文实现，
未作简化。对齐情况由 `tests/cpace-vectors.mjs` 用草案附录 B.3 的官方测试向量逐字节验证。

`sid` 与 `CI` 双方可独立确定，零额外往返。`lo`/`hi` 为按 id 字符串字典序排列的两方，
对应的身份公钥同序排列：

```
DSI = "CPaceRistretto255"
DSI_ISK = "CPaceRistretto255_ISK"
H.s_in_bytes = 128,  H 输出 64 字节,  field_size = 32,  group_size_bits = 252

sid = SHA512( lv_cat("zqchat/v2/sid", roomId, lo, hi, roomNonce, xpkLo, xpkHi) )
CI  =       lv_cat("zqchat/v2/CI",  roomId, lo, hi, ipkLo, ipkHi)

生成元（草案 §8.1/§8.3）：
  len_zpad = MAX(0, 128 − len(prepend_len(PRS)) − len(prepend_len(DSI)) − 1)
  gen_str  = lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)
  G        = element_derivation( SHA512(gen_str)[0:64] )
             （element_derivation = RFC 9496 §4.3.4 from_uniform_bytes）
```

发起方（`cpaceInit`）：

```
a   = sample_scalar()          取 32 字节随机，清除高于 252 位的高位，小端解释为整数
ya  = G · a                    公开；scalar 私留
```

接收方（`cpaceFinish`）：

```
K   = scalar_mult_vfy(a, peerYa)     解码失败或为单位元 → 中止
T   = transcript_oc(ya, ADa, peerYa, ADb)
    = o_cat( lv_cat(ya, ADa), lv_cat(peerYa, ADb) )      b"oc" 前缀 + 字典序较大者在前
ISK = SHA512( lv_cat(DSI_ISK, sid, K) ‖ T )
```

本项目 `ADa`/`ADb` 传空字节串，采用**对称设置**（`transcript_oc`），因握手无强制发起方/响应方顺序。

**安全属性**：密码只影响生成元 `G`。攻击者即使猜对密码并掌握全部公开材料（`ya`、`sid`、`CI`），
也无法离线复现 `ISK`——他缺少对端的临时标量 `a`，因此必须完成一次交互握手才能验证一个猜测。

## 7. 握手状态机

角色由 id 决定：**较小 id 一侧为 ML-KEM 封装方**，写死在 `Session.pair` 的断言里。

```
1. 双方各自 Session.prepare()：算 sid/CI、跑 cpaceInit 得到 ya 与本地标量
2. 双方各发 hs{ya, sig, e}，中继原样转发并用连接身份覆盖 from
   sig = Ed25519( "zqchat/v2/hs" ‖ to ‖ roomNonce ‖ ya ‖ kemCt )
   （kemCt 为空时按空字节串参与签名）
3. 封装方收到对端 ya → pair() 得到 kemCt → 再发一条 hs{ya, kemCt, sig, e}
4. 解封方收到 kemCt → pair()
5. 双方计算 root，各自发送 ctag
6. 验签 ctag：一致则 verified=true，随后互发加密用户名
```

`Session.pair(..., epoch)` 在建链后钉死起始轮次 `rotateTo(epoch, EPOCH_MAX_STEPS)`。
取双方 `hs.e` 的最大值以消除成员广播到达顺序差导致的链路分叉。

`hs.e` **不在签名体内**，是对端完全可控的整数。`_onHs` 拒绝负数与非安全整数；
即便放行，`rotateTo` 的步数闸门（默认 64，上限内才放行）也会拒绝超大跳变并抛 `STATE_DESYNC`。

## 8. 密钥派生

统一 `KDF(ikm, salt, info, len) = HKDF-SHA256(ikm, salt, info, len)`，salt 一律为 `roomId`。

| 用途 | IKM | info | len |
|---|---|---|---|
| 会话根密钥 | `ssX ‖ ssK ‖ ssP` | `zqchat/v2/root{lo}{hi}` | 32 |
| 密码确认标签 | `root` | `zqchat/v2/confirm{lo}{hi}{b64(roomNonce)}` | 16 |
| 安全码 | `root` | `zqchat/v2/fp{lo}{hi}` | 30 |
| 轮换推进 | `root` | `zqchat/v2/rotate{epoch}{lo}{hi}` | 32 |
| 收发链 | `root` | `zqchat/v2/chain{myId}{peerId}`（收方为 `chain{peerId}{myId}`） | 32 |
| 单条消息密钥 | `chain` | `zqchat/v2/msg{n}` | 32 |
| 链推进 | `chain` | `zqchat/v2/chain{n}` | 32 |

其中 `ssX = X25519(自己 _xsk, 对端 xpk)`（全零共享秘密 → `MALFORMED`），
`ssK = ML-KEM-768` 共享秘密，`ssP = CPace ISK`。

安全码 = `hex(fp)`，60 hex，UI 按 4 位一组展示。它绑定会话密钥，中继无法预测；
双方一致即可确认未被中间人替换会话。

## 9. 消息加密与密钥链

发送：

```
mk    = KDF(sendChain, roomId, `zqchat/v2/msg{n}`)
nonce = randomBytes(24)
aad   = { v:2, from:myId, to:peerId, room:roomId, n, e }
        文件分片另加 f = { fid, vi, tv }
ct    = XChaCha20-Poly1305(mk, nonce, JSON(aad)).encrypt( padPayload(JSON(payload)) )
sendChain = KDF(sendChain, roomId, `zqchat/v2/chain{n}`)
输出 = JSON.stringify({ n, e, nonce, to, ct, f? })
```

`payload` 为 `{a:'m', t:<类型>, d:<数据>}`；用户名握手消息为 `{a:'u', p:<用户名>}`。

接收走对称流程，并处理三类落后情形：

- `e > this.epoch` → `rotateTo(e)` 自动追赶（步数上限同 §7）
- `e == this.epoch - 1` 且有 `_prevRecv` → 用保留的上一轮链解密在途消息
- 更早 → `STALE_EPOCH`

序号约束：`n < curSeq - 64` 判 `REPLAY`（过旧），`n >= curSeq + 4096` 判 `STATE_DESYNC`（跳变过大），
本轮内重复 `n` 判 `REPLAY`。

## 10. epoch 轮换

epoch 是中继维护的整数计数器，**不参与密钥计算**，只广播。

- 成员增减 → `bumpEpochSoon()`，5 秒合并窗口后 `epoch++` 并广播 `{t:'epoch', e}`
- 客户端收到后 `_rotateAll(e)`，对每条会话 `rotateTo(e)`
- 每次 `rotateTo` 先保留上一轮接收链（`_prevRecv`）再推进 root，轮换后 seq 归零
- 轮换发生在认证之后，**安全码不变**
- 单次跳变上限 `EPOCH_MAX_STEPS = 64`；越界抛 `STATE_DESYNC`，由 `_rotateAll` 转成 `hsreq` 重建会话

## 11. 填充

```
PAD_BLOCK = 256,  PAD_MAX = 8192
padPayload:  len >= 8192 → 原样返回；否则补到 256 的倍数，首字节写 1 作标记
unpadPayload: p[0] != 1 → 原样返回；否则去掉首字节与尾部 0
```

以首字节判定而非长度判断，修掉了长度 8190~8191 的载荷恰好填满 8192 后无法剥离的死角。
超长载荷不填充，长度会泄露——属已知取舍。

## 12. 错误码

客户端侧（`Err`，抛 `CryptoError`）：

| 码 | 触发 |
|---|---|
| `MALFORMED` | 字段缺失、非 JSON、低阶 X25519 公钥、CPace 退化点、封装角色错配 |
| `AUTH_FAILED` | AEAD 校验失败（密文被篡改） |
| `REPLAY` | 序号重用、改 `to` 转发、落后超过一轮 |
| `STALE_EPOCH` | epoch 回退或落后过多 |
| `STATE_DESYNC` | epoch 或序号跳变过大 → 触发 `hsreq` |
| `PASSWORD_MISMATCH` | confirmTag 不一致 → 丢弃该 peer 会话 |
| `BAD_BUNDLE` | bundle 或握手材料验签失败 |
| `PEER_UNKNOWN` | 保留，当前未使用 |

中继侧 `error.code`：`NONCE_CONFLICT`、`DUPLICATE_ID`、`ROOM_FULL`、`RATE_LIMIT`、`ROOM_RATE_LIMIT`。
关闭码：1008 `DUPLICATE_ID` / `BAD_BUNDLE`，1009 `FRAME_TOO_LARGE`，1013 `ROOM_FULL`。

## 13. 中继侧约束

| 项 | 值 |
|---|---|
| 业务帧上限 | 8 MB |
| 握手类帧上限（hs/ctag/hsreq） | 8192 B |
| 每房间连接数 | 100 |
| 每 IP 连接数 | 10 |
| 每连接令牌桶 | 突发 20，10/s |
| 每房间令牌桶 | 突发 1000，200/s |
| join 限流 | 每连接 3 次 / 10s |
| epoch 合并窗口 | 5 s |
| 心跳超时清理 | 60 s（独立 15 s 定时器） |

Durable Object 以 `idFromName(roomHash)` 分房间。`from` 字段一律以连接绑定的真实身份覆盖，
中继不生成也不信任客户端上报的身份。日志只记元数据，不记载荷。

## 14. 安全属性与已知取舍

**已保证**

- 服务器零密钥：中继只见 bundle 与密文
- 密码不可离线爆破（§6）
- 密码错误显式可辨，不泄露明文
- 握手材料抗重放（`sig` 覆盖 ya/kemCt）
- 混合后量子握手（X25519 + ML-KEM-768）
- AEAD 绑定收发方、房间、序号与 epoch
- 安全码可检测中继替换会话

**已知取舍**

- **密码不是准入凭证**：知道房间名即可加入（看到成员列表、发起在线猜测）。房间名是标识而非凭证，
  人选的短房间名可枚举。
- **salt 无随机成分**：Argon2id salt 是 `sha256(房间名)`，跨部署恒定。但因 CPace 的存在，
  预计算 Argon2 表并不能离线验证猜测，收益有限。
- **Argon2 参数取 OWASP 最低档**（t=2, 19 MiB, p=1），换取移动端可用性。
- **长载荷不填充**，泄露长度。
- **在线猜测残余风险**为 PAKE 固有：一次交互验证一个猜测。当前限流仅在单连接维度。
- **身份私钥存于 localStorage**，XSS 即失长期身份（历史消息不受影响，无历史可泄）。
- **安全码比对是人工步骤**，无密码房间若用户不比对则等于无 MITM 防护。