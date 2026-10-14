// ZQ-Chat v2 Worker 工具 —— 仅路由所需的最小工具集
// v1 的 encryptMessage / decryptMessage / generateRSAKeyPair / generateClientId
// 全部删除：盲中继不需要任何密码学能力（规格 §7.1/§7.4）。

export const getTime = () => Date.now();

export const isString = (v) => Object.prototype.toString.call(v) === '[object String]' && !!v;
export const isArray = (v) => Array.isArray(v);
export const isObject = (v) => v && Object.prototype.toString.call(v) === '[object Object]';

const B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
export function b64dec(str) {
  if (typeof str !== 'string') throw new Error('bad base64');
  const clean = str.replace(/=+$/, '');
  if (/[^A-Za-z0-9+/]/.test(clean)) throw new Error('bad base64 chars');
  const out = new Uint8Array(Math.floor(clean.length * 3 / 4));
  let p = 0, buffer = 0, bits = 0;
  for (let i = 0; i < clean.length; i++) {
    const v = B64C.indexOf(clean[i]);
    if (v < 0) throw new Error('bad base64 char');
    buffer = (buffer << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out[p++] = (buffer >> bits) & 255; }
  }
  return out.slice(0, p);
}
export function b64enc(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 3) {
    const b = u8[i], c = u8[i + 1], d = u8[i + 2];
    s += B64C[b >> 2] + B64C[((b & 3) << 4) | (c === undefined ? 0 : c >> 4)];
    s += c === undefined ? '=' : B64C[((c & 15) << 2) | (d === undefined ? 0 : d >> 6)];
    s += d === undefined ? '=' : B64C[d & 63];
  }
  return s;
}

// v1 缺陷 #8 修复：旧实现 `level !== 'debug' || true` 恒真，且会打印解密后的载荷。
// v2 日志只允许元数据（id、错误码、计数），绝不接触消息内容。
export function logEvent(source, meta) {
  console.log(`[${new Date().toISOString()}] ${source}${meta !== undefined ? ': ' + meta : ''}`);
}
