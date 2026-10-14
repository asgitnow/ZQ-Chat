// 校验文档中出现的导出符号在源码中确实存在（防止文档漂移）
import fs from 'node:fs';
import * as cpace from '../client/js/zqcpace.mjs';
import * as crypto from '../client/js/zqcrypto.mjs';

const DOCS = ['README.md', 'doc/spec-v2.md', 'doc/api.md'];

const exportsOf = (mod) => new Set(Object.keys(mod));
const known = new Set([...exportsOf(cpace), ...exportsOf(crypto)]);

// 文档里出现的、看起来像模块符号的标识符
const CANDIDATES = [
  'cpaceContext', 'cpaceInit', 'cpaceFinish', 'cpaceGenerator', 'calculateGenerator',
  'generatorString', 'sampleScalar', 'scalarMultVfy',
  'prependLen', 'lvCat', 'oCat', 'transcriptIr', 'transcriptOc', 'DSI',
  'Identity', 'Session', 'Err', 'CryptoError', 'b64', 'unb64', 'KDF', 'PROTO',
  'padPayload', 'unpadPayload', 'PAD_BLOCK', 'PAD_MAX', 'stretchArgon2id',
  'ARGON2_PARAMS', 'ROOM_NONCE_LEN', 'EPOCH_MAX_STEPS', 'TokenBucket',
  'hashToCurve', 'hashToScalar', 'lp', 'simpleEncrypt', 'simpleDecrypt',
];

let bad = 0;
for (const doc of DOCS) {
  const text = fs.readFileSync(doc, 'utf8');
  for (const name of CANDIDATES) {
    if (!text.includes(name)) continue;
    if (known.has(name)) continue;
    // 出现在文档里，但源码没有这个导出
    bad++;
    console.log(`  ❌ ${doc}: 引用了 '${name}'，但源码未导出`);
  }
}

export function checkDocRefs() {
	let bad = 0;
	for (const doc of DOCS) {
		const text = fs.readFileSync(doc, 'utf8');
		for (const name of CANDIDATES) {
			if (!text.includes(name)) continue;
			if (known.has(name)) continue;
			bad++;
			console.log(`  ❌ ${doc}: 引用了 '${name}'，但源码未导出`);
		}
	}
	return bad;
}

// 独立运行
if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, '/')}`) {
	const bad = checkDocRefs();
	console.log(`\n已导出符号共 ${known.size} 个；文档中失效引用 ${bad} 处`);
	if (bad === 0) console.log('  ✅ 文档引用的模块符号全部存在');
	process.exit(bad ? 1 : 0);
}