/**
 * The hashes against published vectors: DSTU 7564 (the examples of the standard and the Kupyna paper), GOST 34.311
 * (GOST R 34.11-94 with the "test" and CryptoPro tables), and SHA-1/SHA-256 against Node's crypto.
 */
import { createHash, randomBytes } from 'node:crypto';
import { checker, load } from '../tools/load.mjs';

const H = await load('core/hash/dstu7564', 'core/hash/gost', 'core/hash/sha', 'core/bytes');
const { check, done } = checker();
const seq = (n) => Uint8Array.from({ length: n }, (_, i) => i & 0xff);
const ascii = (s) => new TextEncoder().encode(s);

for (const [bits, message, expected] of [
  [256, seq(64), '08F4EE6F1BE6903B324C4E27990CB24EF69DD58DBE84813EE0A52F6631239875'],
  [256, seq(128), '0A9474E645A7D25E255E9E89FFF42EC7EB31349007059284F0B182E452BDA882'],
  [256, seq(256), 'D305A32B963D149DC765F68594505D4077024F836C1BF03806E1624CE176C08F'],
  [256, Uint8Array.of(0xff), 'EA7677CA4526555680441C117982EA14059EA6D0D7124D6ECDB3DEEC49E890F4'],
  [256, seq(95), '1075C8B0CB910F116BDA5FA1F19C29CF8ECC75CAFF7208BA2994B68FC56E8D16'],
  [256, seq(0), 'CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6'],
  [384, seq(95), 'D9021692D84E5175735654846BA751E6D0ED0FAC36DFBC0841287DCB0B5584C75016C3DECC2A6E47C50B2F3811E351B8'],
  [512, seq(64), '3813E2109118CDFB5A6D5E72F7208DCCC80A2DFB3AFDFB02F46992B5EDBE536B3560DD1D7E29C6F53978AF58B444E37BA685C0DD910533BA5D78EFFFC13DE62A'],
  [512, seq(128), '76ED1AC28B1D0143013FFA87213B4090B356441263C13E03FA060A8CADA32B979635657F256B15D5FCA4A174DE029F0B1B4387C878FCC1C00E8705D783FD7FFE'],
  [512, seq(256), '0DD03D7350C409CB3C29C25893A0724F6B133FA8B9EB90A64D1A8FA93B56556611EB187D715A956B107E3BFC76482298133A9CE8CBC0BD5E1436A5B197284F7E'],
  [512, Uint8Array.of(0xff), '871B18CF754B72740307A97B449ABEB32B64444CC0D5A4D65830AE5456837A72D8458F12C8F06C98C616ABE11897F86263B5CB77C420FB375374BEC52B6D0292'],
  [512, seq(192), 'B189BFE987F682F5F167F0D7FA565330E126B6E592B1C55D44299064EF95B1A57F3C2D0ECF17869D1D199EBBD02E8857FB8ADD67A8C31F56CD82C016CF743121'],
  [512, seq(0), '656B2F4CD71462388B64A37043EA55DBE445D452AECD46C3298343314EF04019BCFA3F04265A9857F91BE91FCE197096187CEDA78C9C1C021C294A0689198538'],
]) {
  check(`DSTU 7564-${bits}, ${message.length} bytes`, H.toHex(H.Dstu7564.hash(message, bits)), expected);
}
for (const [message, expected] of [
  ['', 'CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6'],
  ['a', 'C51A1D639596FB613D86557314A150C40F8FFF3DE48BC93A3B03C161F4105EE4'],
  ['abc', '0BD1B36109F1318411A0517315AA46B8839DF06622A278676F5487996C9CFC04'],
  ['abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu', '02621DBB53F2C7001BE64D7308ECB80D21BA7797C92E98D1EFC240D41E4C414B'],
]) {
  check(`DSTU 7564-256 '${message.slice(0, 10)}'`, H.toHex(H.Dstu7564.hash(ascii(message))), expected);
}
// Incremental updates across block boundaries give the one-shot result.
{
  const data = randomBytes(1001);
  for (const bits of [256, 512]) {
    const h = new H.Dstu7564(bits);
    let offset = 0;
    for (const chunk of [1, 63, 2, 128, 300, 7, 500]) {
      h.update(data.subarray(offset, offset + chunk));
      offset += chunk;
    }
    check(`DSTU 7564-${bits} incremental`, H.toHex(h.digest()), H.toHex(H.Dstu7564.hash(data, bits)));
  }
}

// GOST R 34.11-94 "test" parameter set (RFC 5831): the DKE of UCC is that table.
const TEST_DKE = H.fromHex('4A92D80E6B1C7F53EB4C6DFA23810759581DA342EFC7609B7DA1089FE46CB2536C715FD84A9E03B24BA0721D36859CFEDB413F590AE7682C1FD057A4923E6B8C');
for (const [message, expected] of [
  ['', 'CE85B99CC46752FFFEE35CAB9A7B0278ABB4C2D2055CFF685AF4912C49490F8D'],
  ['a', 'D42C539E367C66E9C88A801F6649349C21871B4344C6A573F849FDCE62F314DD'],
  ['message digest', 'AD4434ECB18F2C99B60CBE59EC3D2469582B65273F48DE72DB2FDE16A4889A4D'],
  ['The quick brown fox jumps over the lazy dog', '77B7FA410C9AC58A25F49BCA7D0468C9296529315EACA76BD1A10F376D1F4294'],
]) {
  check(`GOST 34.311 test table '${message}'`, H.toHex(H.Gost34311.hash(ascii(message), TEST_DKE)), expected);
}
// The block cipher decrypts what it encrypts.
{
  const g = new H.Gost28147(H.expandDke(H.DEFAULT_DKE));
  const key = randomBytes(32);
  g.setKey(key);
  const block = randomBytes(8);
  const enc = new Uint8Array(8);
  const dec = new Uint8Array(8);
  g.encryptBlock(block, 0, enc, 0);
  g.decryptBlock(enc, 0, dec, 0);
  check('GOST 28147 round trip', H.toHex(dec), H.toHex(block));
}

for (const length of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000]) {
  const data = randomBytes(length);
  check(`SHA-1, ${length} bytes`, H.toHex(H.sha1(data)), createHash('sha1').update(data).digest('hex').toUpperCase());
  check(`SHA-256, ${length} bytes`, H.toHex(H.sha256(data)), createHash('sha256').update(data).digest('hex').toUpperCase());
}

done('hash');
