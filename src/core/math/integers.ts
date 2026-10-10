import { bitLength, bytesToBigInt } from '../bytes';
import { randomBytes } from '../random';

/** base^exponent mod modulus, for exponent ≥ 0. */
export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n % modulus;
  let b = ((base % modulus) + modulus) % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

/** Miller–Rabin with random bases, as DSTU 4145-2002, 6.12 asks. */
export function isProbablePrime(n: bigint, rounds = 50): boolean {
  if (n < 2n) return false;
  for (const small of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n === small) return true;
    if (n % small === 0n) return false;
  }
  let j = n - 1n;
  let k = 0;
  while ((j & 1n) === 0n) {
    j >>= 1n;
    k++;
  }
  const bytes = Math.ceil(bitLength(n) / 8);
  for (let i = 0; i < rounds; i++) {
    let a: bigint;
    do a = bytesToBigInt(randomBytes(bytes)) % n;
    while (a < 2n);
    let b = modPow(a, j, n);
    if (b === 1n || b === n - 1n) continue;
    let composite = true;
    for (let l = 1; l < k; l++) {
      b = (b * b) % n;
      if (b === n - 1n) {
        composite = false;
        break;
      }
      if (b === 1n) return false;
    }
    if (composite) return false;
  }
  return true;
}

/** ⌊√n⌋ for n ≥ 0. */
export function integerSqrt(n: bigint): bigint {
  if (n < 0n) throw new Error('Negative value.');
  if (n < 2n) return n;
  let x = 1n << BigInt(Math.ceil(bitLength(n) / 2));
  for (;;) {
    const y = (x + n / x) >> 1n;
    if (y >= x) return x;
    x = y;
  }
}
