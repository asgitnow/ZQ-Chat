// CPace 草案官方测试向量 —— draft-irtf-cfrg-cpace-21 附录 B.3
// 密码套件 CPACE-RISTR255-SHA512。用于证明本实现与规范逐字节一致。
// 期望值全部取自草案正文与其 B.3.1.1 的 base64 JSON，不做任何手工转录。
import {
  prependLen, lvCat, oCat, transcriptOc, transcriptIr,
  generatorString, calculateGenerator, scalarMultVfy, cpaceFinish, enc,
} from '../client/js/zqcpace.mjs';

const H = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('').toLowerCase();
const fromHex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const leToBigInt = (b) => { let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return x; };

// —— 草案 B.3.1.1 官方 JSON（generator_string 与 hash result 的权威来源）——
const B31_JSON = {
  PRS: '50617373776F7264',
  DSI: '435061636552697374726574746F323535',
  CI: '0B415F696E69746961746F720B425F726573706F6E646572',
  sid: '7E4B4791D6A8EF019B936C79FB7F2C57',
  generator_string: '11435061636552697374726574746f3235350850617373776f72646400000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '180b415f696e69746961746f720b425f726573706f6e646572107e4b4791d6a8' +
    'ef019b936c79fb7f2c57',
  'hash result': 'DA6D3DDC8802FCA9058755FFD3EBDE08A9C2C74945901A258482A288' +
    'B6663AF06BF645C93CD1C51512307199C80E84908916D983B34AF77205F90851A657EE27',
  'encoded generator g': '222B6B195FE84B1652BADB6F6A3AE3D24341E7306967F0B8115B40D5698C7E56',
};

const PRS = fromHex(B31_JSON.PRS);
const CI = fromHex(B31_JSON.CI);
const sid = fromHex(B31_JSON.sid);

/** 供 crypto.test.mjs 调用的向量校验 */
export function checkVectors(ok) {
  // —— B.3.1 calculate_generator ——
  const genStr = generatorString(enc('CPaceRistretto255'), PRS, CI, sid, 128);
  ok(H(genStr) === B31_JSON.generator_string.toLowerCase(),
    'B.3.1 generator_string 逐字节一致', `${genStr.length} 字节`);
  ok(H(calculateGenerator(PRS, CI, sid).toBytes()) === B31_JSON['encoded generator g'].toLowerCase(),
    'B.3.1 生成元 g 一致（element_derivation = RFC 9496 §4.3.4）');

  // —— B.3.2 / B.3.3 消息 ——
  const ya = leToBigInt(fromHex('da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08'));
  const yb = leToBigInt(fromHex('d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d'));
  const g = calculateGenerator(PRS, CI, sid);
  const Ya = g.multiply(ya).toBytes();
  const Yb = g.multiply(yb).toBytes();
  ok(H(Ya) === 'd6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157', 'B.3.2 Ya 一致');
  ok(H(Yb) === '3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258', 'B.3.3 Yb 一致');

  // —— B.3.4 K ——
  const K = '80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f';
  ok(H(scalarMultVfy(ya, Yb)) === K, 'B.3.4 scalar_mult_vfy(ya,Yb) = K');
  ok(H(scalarMultVfy(yb, Ya)) === K, 'B.3.4 scalar_mult_vfy(yb,Ya) = K（双方一致）');

  // —— B.3.5 / B.3.6 transcript 与 ISK ——
  const ADa = enc('ADa'), ADb = enc('ADb');
  ok(H(transcriptIr(Ya, ADa, Yb, ADb)) ===
    '20d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b915703414461' +
    '203ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f725803414462',
    'B.3.5 transcript_ir 一致');
  ok(H(transcriptOc(Ya, ADa, Yb, ADb)) ===
    '6f6320d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b915703414461' +
    '203ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f725803414462',
    'B.3.6 transcript_oc 一致');
  ok(H(cpaceFinish(ya, Yb, Ya, sid, CI, ADa, ADb, 'ir')) ===
    'b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dcae7b35cd2' +
    'b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c3fa2068af7900447',
    'B.3.5 ISK（initiator/responder 设置）一致');
  ok(H(cpaceFinish(ya, Yb, Ya, sid, CI, ADa, ADb, 'symmetric')) ===
    '544199d71f62f8d9a1fee55727e24fe4a45844593c2b6013c4fa3969' +
    'd0e5debb2244675c0b43397cbb68d342b01fc0f98fc961469a25134de9f0f813c1a57476',
    'B.3.6 ISK（对称设置，本项目采用的设置）一致');

  // —— 附录 A.1 / A.3 字符串运算 ——
  ok(H(prependLen(new Uint8Array(0))) === '00', 'prepend_len("") = 00');
  ok(H(prependLen(enc('Password'))) === '0850617373776f7264', 'prepend_len("Password")');
  ok(H(prependLen(new Uint8Array(200).fill(9))) === 'c801' + '09'.repeat(200),
    'prepend_len 变长编码（200 → c8 01）');
  ok(H(lvCat(enc('a'), enc('b'))) === '01610162', 'lv_cat(b"a",b"b")');
  ok(H(oCat(enc('a'), enc('b'))) === '6f63' + '62' + '61', 'o_cat(b"a",b"b") = b"oc" ‖ 较大者在前');
}

// 独立运行
if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, '/')}`) {
  let pass = 0, fail = 0;
  console.log('\n⑥ CPace 草案官方测试向量（draft-irtf-cfrg-cpace-21 附录 B.3）');
  checkVectors((c, n, x = '') => {
    if (c) { pass++; console.log(`  ✅ ${n}${x ? '  — ' + x : ''}`); }
    else { fail++; console.log(`  ❌ ${n}`); }
  });
  console.log(`\n${'─'.repeat(52)}\n官方向量: ${pass} 项通过, ${fail} 项失败\n${'─'.repeat(52)}`);
  process.exit(fail ? 1 : 0);
}