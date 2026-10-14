// Argon2id 异步拉伸的 Web Worker 载体（浏览器 & Node 24 通用）
// 规格 §4.4：MUST 用异步方式完成 ~200ms 的拉伸，避免阻塞主线程
import { argon2id } from '@noble/hashes/argon2.js';

self.onmessage = (ev) => {
  const { id, password, roomId, params } = ev.data;
  try {
    const te = new TextEncoder();
    const out = argon2id(te.encode(password), te.encode(roomId), params);
    self.postMessage({ id, ok: true, prs: out }, { transfer: [out.buffer] });
  } catch (e) {
    self.postMessage({ id, ok: false, error: String(e && e.message || e) });
  }
};
