# ZQ-Chat v2 线上帧协议

所有帧为 JSON 文本；二进制字段标准 base64。服务器只见这些帧，无任何解密能力。

## 客户端 → 服务器

| 帧 | 说明 |
|---|---|
| `{t:"nonce"}` | 连接建立后第一帧；询问房间权威 roomNonce |
| `{t:"join", bundle, nonce}` | bundle={id,ipk,xpk,kpk,sig}（sig 覆盖 id‖ipk‖xpk‖kpk‖roomNonce）；nonce=b64(16B) |
| `{t:"hs", to, ya, kemCt, e, sig}` | 握手材料；封装方(id较小)后发一条带 kemCt 的 hs；sig=Ed25519("zqchat/v2/hs"‖to‖roomNonce‖epoch(4B)‖ya‖kemCt) |
| `{t:"ctag", to, tag, e}` | 密码确认标签（16B，root 派生，不混入 epoch） |
| `{t:"hsreq", to}` | STATE_DESYNC 时请求对端重建会话 |
| `{t:"msg", to:[id…], c:[wire…]}` | 广播/单聊；c[i] 为 Session.encrypt 的线上包（含 n/e/nonce/ct/to，文件分片另带 f） |
| `"ping"` | 心跳 |

## 服务器 → 客户端

| 帧 | 说明 |
|---|---|
| `{t:"nonce", nonce, epoch}` | nonce=null 表示空房间，由本客户端提供 |
| `{t:"joined", members, epoch, nonce}` | join 成功；members 为其余成员的 bundle 列表 |
| `{t:"member.add", bundle, epoch}` / `{t:"member.gone", id, epoch}` | 成员事件（立即送达） |
| `{t:"epoch", e}` | 5s 合并窗口后的轮换计数 |
| `{t:"hs"/"ctag"/"hsreq", from, …}` | 转发（from 由中继绑定为真实连接身份，防冒充） |
| `{t:"msg", from, c}` | 单播转发 |
| `{t:"error", code, nonce?}` | NONCE_CONFLICT / DUPLICATE_ID / ROOM_FULL / RATE_LIMIT |

约束：握手类 ≤8192B；业务 ≤8MB；每连接令牌桶(20,10/s)、每房间(1000,200/s)；
join/完整握手 ≤3 次/10s；每房间 ≤100 连接、每 IP ≤10；bundle 验签失败断连(1008)。
DO 以 idFromName(roomHash) 分房间；from 字段一律以连接绑定身份覆盖。
配对起始轮次 = max(双方 hs 携带的 e)；本地计数器更高者配对后立即 rotateTo 追赶。
