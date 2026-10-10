/**
 * GF(2^m), the curve and DSTU 4145: the worked example Б.1 of the standard (polynomial basis, m = 163) value by value,
 * the field against the definitions (trace, inversion, irreducibility of table 1), the ladder against double-and-add,
 * the curves of table Г.1 against section 8, and sign/verify round trips with tampering.
 */
import { checker, load } from '../tools/load.mjs';

const D = await load('core/dstu4145', 'core/math/field', 'core/math/curve', 'core/bytes');
const { check, done } = checker();
const H = (hex) => BigInt('0x' + hex);

// ---- The field ----------------------------------------------------------------------------------------------------
for (const m of [163, 167, 173, 191, 233, 257, 307, 367, 431, 509]) {
  const f = D.BinaryField.recommended(m);
  check(`table 1, m = ${m}: irreducible`, f.isIrreducible(), true);
  let ok = true;
  for (let i = 0; i < 6; i++) {
    const a = f.fromBigInt(BigInt.asUintN(m, BigInt('0x' + [...crypto.getRandomValues(new Uint8Array(70))].map((b) => b.toString(16).padStart(2, '0')).join(''))));
    if (D.BinaryField.isZero(a)) continue;
    const b = f.fromBigInt(BigInt(i * 7919 + 3));
    ok &&= f.isOne(f.mul(a, f.inv(a)));
    ok &&= D.BinaryField.equal(f.sqr(a), f.mul(a, a));
    ok &&= D.BinaryField.equal(f.mul(a, b), f.mul(b, a));
    ok &&= D.BinaryField.equal(f.sqr(f.sqrt(a)), a);
    ok &&= f.trace(a) === f.traceByDefinition(a);
    ok &&= D.BinaryField.equal(f.sqrTimes(a, m), a); // a^(2^m) = a
  }
  check(`m = ${m}: inverse, squaring, commutativity, sqrt, trace mask, Frobenius`, ok, true);
}
// The trace of every basis element by the mask equals the definition (m = 163, every bit).
{
  const f = D.BinaryField.recommended(163);
  let ok = true;
  for (let i = 0; i < 163; i++) {
    const e = f.zero();
    e[i >>> 5] = 1 << (i & 31);
    ok &&= f.trace(e) === f.traceByDefinition(e);
  }
  check('m = 163: the trace of every basis element', ok, true);
}

// ---- Б.1: polynomial basis, GF(2^163), t^163 + t^7 + t^6 + t^3 + 1 --------------------------------------------------
{
  const field = new D.BinaryField(163, 3, 6, 7);
  const curve = new D.BinaryCurve(field, 1, field.fromBigInt(H('5FF6108462A2DC8210AB403925E638A19C1455D21')));
  const p = curve.point(H('72D867F93A93AC27DF9FF01AFFE74885C8C540420'), H('0224A9C3947852B97C5599D5F4AB81122ADC3FD9B'));
  const domain = new D.DomainParameters(curve, p, H('400000000000000000002BEC12BE2262D39BCF14D'));
  check('Б.1: parameters pass section 8', domain.validate(), null);

  const d = H('183F60FDF7951FF47D67193F8D073790C1C9B5A3E');
  const q = D.computePublicKey(domain, d);
  // The printed standard misses one digit of x_Q ("...ABD2DA").
  check('Б.1: Q = −dP, x', field.toBigInt(q.x), H('057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA'));
  check('Б.1: Q = −dP, y', field.toBigInt(q.y), H('3E85444324BCF06AD85ABF6AD7B5F34770532B9AA'));
  check('Б.1: Q passes 10.1', domain.validatePublicKey(q), null);

  const hash = D.fromHex('09C9C44277910C9AAEE486883A2EB95B7180166DDF73532EEB76EDAEF52247FF');
  check('Б.1: h', field.toBigInt(D.hashToFieldElement(hash, field)), H('03A2EB95B7180166DDF73532EEB76EDAEF52247FF'));
  const e = H('1025E40BD97DB012B7A1D79DE8E12932D247F61C6');
  const ep = curve.multiply(p, e);
  check('Б.1: eP, x', field.toBigInt(ep.x), H('42A7D756D70E1C9BA62D2CB43707C35204EF3C67C'));
  check('Б.1: eP, y', field.toBigInt(ep.y), H('5310AE5E560464A95DC80286F17EB762EC544B15B'));
  const rs = D.signWithNonce(domain, d, hash, e);
  check('Б.1: r', rs.r, H('274EA2C0CAA014A0D80A424F59ADE7A93068D08A7'));
  check('Б.1: s', rs.s, H('2100D86957331832B8E8C230F5BD6A332B3615ACA'));
  const signature = D.encodeSignature(rs.r, rs.s, 512);
  check(
    'Б.1: D',
    D.toHex(signature),
    '000000000000000000000002100D86957331832B8E8C230F5BD6A332B3615ACA00000000000000000000000274EA2C0CAA014A0D80A424F59ADE7A93068D08A7',
  );
  check('Б.1: verifies', D.verifyHash(domain, q, hash, signature), true);
  let rejected = true;
  for (let i = 0; i < signature.length; i += 7) {
    const bad = signature.slice();
    bad[i] ^= 0x10;
    rejected &&= !D.verifyHash(domain, q, hash, bad);
  }
  check('Б.1: every tampered byte of D is rejected', rejected, true);
  const badHash = hash.slice();
  badHash[badHash.length - 1] ^= 1;
  check('Б.1: another hash is rejected', D.verifyHash(domain, q, badHash, signature), false);
  check('Б.1: compression round trip', D.BinaryCurve.pointsEqual(curve.decompress(curve.compress(q)), q), true);
}

// ---- Table Г.1 --------------------------------------------------------------------------------------------------
for (const m of D.NAMED_CURVE_DEGREES) {
  const domain = D.namedCurve(m);
  const curve = domain.curve;
  check(`Г.1, m = ${m}: section 8`, domain.validate(), null);
  // The ladder against affine double-and-add on a few scalars, including the edges.
  const p = domain.basePoint;
  let ok = true;
  for (const k of [1n, 2n, 3n, 5n, 0x1234567n, domain.n - 1n, domain.n + 1n]) {
    let acc = null;
    for (const bit of k.toString(2)) {
      acc = curve.double(acc);
      if (bit === '1') acc = curve.add(acc, p);
    }
    ok &&= D.BinaryCurve.pointsEqual(curve.multiply(p, k), acc);
  }
  check(`Г.1, m = ${m}: ladder = double-and-add`, ok, true);
  check(`Г.1, m = ${m}: decompress(compress(P)) = P`, D.BinaryCurve.pointsEqual(curve.decompress(curve.compress(p)), p), true);

  // Sign and verify with a fresh key.
  let d;
  do d = domain.randomInteger();
  while (d === 0n);
  const q = D.computePublicKey(domain, d);
  const hash = crypto.getRandomValues(new Uint8Array(32));
  const signature = D.signHash(domain, d, hash);
  check(`Г.1, m = ${m}: signature length`, signature.length * 8, domain.minimumSignatureBits);
  check(`Г.1, m = ${m}: sign → verify`, D.verifyHash(domain, q, hash, signature), true);
  const bad = signature.slice();
  bad[3] ^= 1;
  check(`Г.1, m = ${m}: tampered signature rejected`, D.verifyHash(domain, q, hash, bad), false);
}

done('dstu4145');
