'use strict';
/* ═══════════════════════════════════════════════════════
   AURORA ORACLE · SUPREME API v4
   78 algorithms · parity voting · auto-settle · auto-skip
   ═══════════════════════════════════════════════════════ */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

/* ─── CONFIG ─── */
const PORT          = process.env.PORT || 3000;
const SOURCE_API    = 'https://get-md5-lc79.onrender.com/';
const ADMIN         = '@DENIUS09';
const MIN_BALANCE   = 3;        // balance < 3  → BỎ QUA (yêu cầu > 2)
const CACHE_TTL     = 4000;     // cache nguồn 4s
const FETCH_TIMEOUT = 25000;
const HISTORY_FILE  = path.join(__dirname, 'history.json');

/* ═══════════════════════════════════════════════════════
   UTILITIES
   ═══════════════════════════════════════════════════════ */
const hexBytes = h => {
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  return b;
};
const pc32 = v => {
  v = v >>> 0;
  v = v - ((v >>> 1) & 0x55555555);
  v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
  v = (v + (v >>> 4)) & 0x0F0F0F0F;
  return (v * 0x01010101) >>> 24;
};
const pcBig = v => {
  let c = 0;
  while (v > 0n) { c += Number(v & 1n); v >>= 1n; }
  return c;
};
const rol32 = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
const ror32 = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

/* AES S-Box */
const SBOX = new Uint8Array([
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]);

/* ═══════════════════════════════════════════════════════
   FULL ALGORITHM SUITE (78 algorithms - 100% từ file gốc)
   ═══════════════════════════════════════════════════════ */
const ALGOS = [
  /* ─── BIT FAMILY (1-16) ─── */
  { name: 'XOR-CHAIN', fn: hex => {
    const b = hexBytes(hex); let x = 0;
    for (let i = 0; i < 16; i++) x = (x ^ b[i]) & 0xFF;
    return { vote: pc32(x) & 1, weight: 2.0 };
  }},
  { name: 'BIT-POPCOUNT', fn: hex => {
    const b = hexBytes(hex); let pc = 0;
    for (let i = 0; i < 16; i++) pc += pc32(b[i]);
    return { vote: pc & 1, weight: 2.2 };
  }},
  { name: 'BYTE-SUM', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let i = 0; i < 16; i++) s = (s + b[i]) & 0xFF;
    return { vote: pc32(s) & 1, weight: 1.8 };
  }},
  { name: 'REV-128', fn: hex => {
    let r = '';
    for (let i = 31; i >= 0; i--) r += hex[i];
    const b = hexBytes(r); let pc = 0;
    for (let i = 0; i < 16; i++) pc += pc32(b[i]);
    return { vote: pc & 1, weight: 1.9 };
  }},
  { name: 'GRAY-CODE', fn: hex => {
    const b = hexBytes(hex); let g = 0;
    for (let i = 0; i < 16; i++) g = (g + (b[i] ^ (b[i] >>> 1))) & 0xFFFF;
    return { vote: pc32(g) & 1, weight: 1.7 };
  }},
  { name: 'BIT-PLANE-0', fn: hex => {
    const b = hexBytes(hex); let pc = 0;
    for (let i = 0; i < 16; i++) pc += b[i] & 1;
    return { vote: pc & 1, weight: 1.6 };
  }},
  { name: 'BIT-PLANE-7', fn: hex => {
    const b = hexBytes(hex); let pc = 0;
    for (let i = 0; i < 16; i++) pc += (b[i] >> 7) & 1;
    return { vote: pc & 1, weight: 1.6 };
  }},
  { name: 'BIT-PLANE-3', fn: hex => {
    const b = hexBytes(hex); let pc = 0;
    for (let i = 0; i < 16; i++) pc += (b[i] >> 3) & 1;
    return { vote: pc & 1, weight: 1.6 };
  }},
  { name: 'ADJ-XOR', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let i = 0; i < 15; i++) acc = (acc + (b[i] ^ b[i+1])) & 0xFFFF;
    return { vote: pc32(acc) & 1, weight: 1.9 };
  }},
  { name: 'NIBBLE-SUM', fn: hex => {
    let s = 0;
    for (let i = 0; i < 32; i++) s = (s + parseInt(hex[i], 16)) & 0xFF;
    return { vote: pc32(s) & 1, weight: 1.7 };
  }},
  { name: 'NIBBLE-PROD', fn: hex => {
    let p = 1;
    for (let i = 0; i < 32; i++) p = (p * (parseInt(hex[i], 16) + 1)) & 0xFFFF;
    return { vote: pc32(p) & 1, weight: 1.8 };
  }},
  { name: 'SHIFT-ROT', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let i = 0; i < 16; i++){
      acc = ((acc << 3) | (acc >>> 29)) >>> 0;
      acc = (acc + b[i]) >>> 0;
    }
    return { vote: pc32(acc) & 1, weight: 2.0 };
  }},
  { name: 'PAIR-SWAP', fn: hex => {
    let swapped = '';
    for (let i = 0; i < 32; i += 2) swapped += hex[i+1] + hex[i];
    const b = hexBytes(swapped); let pc = 0;
    for (let i = 0; i < 16; i++) pc += pc32(b[i]);
    return { vote: pc & 1, weight: 1.8 };
  }},
  { name: 'BIT-REVERSE', fn: hex => {
    const b = hexBytes(hex); let pc = 0;
    for (let i = 0; i < 16; i++){
      let r = 0, v = b[i];
      for (let j = 0; j < 8; j++){ r = ((r << 1) | (v & 1)) & 0xFF; v >>= 1; }
      pc += pc32(r);
    }
    return { vote: pc & 1, weight: 1.9 };
  }},
  { name: 'TRIPLE-XOR', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let i = 0; i < 14; i++) acc = (acc + (b[i] ^ b[i+1] ^ b[i+2])) & 0xFFFF;
    return { vote: pc32(acc) & 1, weight: 2.0 };
  }},
  { name: 'HIGH-LOW', fn: hex => {
    const b = hexBytes(hex); let hi = 0, lo = 0;
    for (let i = 0; i < 16; i++){ hi += (b[i] >> 4) & 0xF; lo += b[i] & 0xF; }
    return { vote: (hi ^ lo) & 1, weight: 1.7 };
  }},

  /* ─── ARITHMETIC (17-28) ─── */
  { name: 'PROD-MOD', fn: hex => {
    const b = hexBytes(hex); let p = 1;
    for (let i = 0; i < 16; i++) p = Math.imul(p, b[i] + 1) >>> 0;
    return { vote: pc32(p) & 1, weight: 2.1 };
  }},
  { name: 'HALF-XOR', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let i = 0; i < 8; i++) acc = (acc + (b[i] ^ b[i+8])) & 0xFF;
    return { vote: pc32(acc) & 1, weight: 1.8 };
  }},
  { name: 'DIFF-CHAIN', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let i = 1; i < 16; i++) acc = (acc + Math.abs(b[i] - b[i-1])) & 0xFFFF;
    return { vote: pc32(acc) & 1, weight: 1.7 };
  }},
  { name: 'LCG-STEP', fn: hex => {
    const b = hexBytes(hex); let x = 0x811c9dc5;
    for (let i = 0; i < 16; i++) x = (Math.imul(x, 1103515245) + b[i] + 12345) >>> 0;
    return { vote: pc32(x) & 1, weight: 2.3 };
  }},
  { name: 'FEISTEL-R', fn: hex => {
    const b = hexBytes(hex); let l = 0, r = 0;
    for (let i = 0; i < 8; i++) l = ((l << 8) | b[i]) >>> 0;
    for (let i = 8; i < 16; i++) r = ((r << 8) | b[i]) >>> 0;
    const f = (rol32(r, 7) ^ (r >>> 5)) >>> 0;
    return { vote: pc32(l ^ f) & 1, weight: 2.2 };
  }},
  { name: 'MULT-16', fn: hex => {
    const b = hexBytes(hex); let acc = 1;
    for (let i = 0; i < 16; i += 2){
      const w = (b[i] << 8) | b[i+1];
      acc = Math.imul(acc, w + 1) >>> 0;
    }
    return { vote: pc32(acc) & 1, weight: 2.1 };
  }},
  { name: 'ADD-ROT', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let i = 0; i < 16; i++) acc = (acc + rol32(b[i], i % 8)) >>> 0;
    return { vote: pc32(acc) & 1, weight: 1.9 };
  }},
  { name: 'PARITY-SUM', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let i = 0; i < 16; i++) s += b[i];
    return { vote: s & 1, weight: 1.7 };
  }},
  { name: 'MULT-XOR', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let i = 0; i < 16; i += 2){
      const w = (b[i] << 8) | b[i+1];
      acc ^= Math.imul(w, 0x9E3779B1) >>> 0;
    }
    return { vote: pc32(acc) & 1, weight: 2.1 };
  }},
  { name: 'MOD-PRIME', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    const p = 1000003;
    for (let i = 0; i < 16; i++) acc = (acc * 257 + b[i]) % p;
    return { vote: acc & 1, weight: 1.9 };
  }},
  { name: 'FIB-HASH', fn: hex => {
    const b = hexBytes(hex); let h = 0;
    const K = 0x9E3779B9;
    for (let i = 0; i < 16; i++) h = Math.imul(h ^ b[i], K) >>> 0;
    return { vote: pc32(h) & 1, weight: 2.2 };
  }},
  { name: 'JENKINS-1', fn: hex => {
    const b = hexBytes(hex); let h = 0;
    for (let i = 0; i < 16; i++){
      h = (h + b[i]) >>> 0;
      h = (h + (h << 10)) >>> 0;
      h ^= h >>> 6;
    }
    h = (h + (h << 3)) >>> 0;
    h ^= h >>> 11;
    h = (h + (h << 15)) >>> 0;
    return { vote: pc32(h) & 1, weight: 2.2 };
  }},

  /* ─── CRYPTO (29-62) ─── */
  { name: 'AES-SBOX', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let i = 0; i < 16; i++) s = (s + SBOX[b[i]]) & 0xFF;
    return { vote: pc32(s) & 1, weight: 2.4 };
  }},
  { name: 'SPN-ROUND', fn: hex => {
    const b = hexBytes(hex);
    const st = new Uint8Array(16);
    for (let i = 0; i < 16; i++) st[i] = SBOX[b[i]];
    for (let i = 0; i < 16; i++) st[i] = rol32(st[i], i % 8) & 0xFF;
    let s = 0;
    for (let i = 0; i < 16; i++) s = (s + st[i]) & 0xFF;
    return { vote: pc32(s) & 1, weight: 2.3 };
  }},
  { name: 'CHACHA-QR', fn: hex => {
    const b = hexBytes(hex);
    let a = 0x61707865, bb = 0x3320646e, c = 0x79622d32, d = 0x6b206574;
    for (let i = 0; i < 16; i += 4){
      const m0 = (b[i] << 24) | (b[i+1] << 16) | (b[i+2] << 8) | b[i+3];
      a = (a + bb + m0) >>> 0; d = rol32(d ^ a, 16);
      c = (c + d) >>> 0; bb = rol32(bb ^ c, 12);
      a = (a + bb) >>> 0; d = rol32(d ^ a, 8);
      c = (c + d) >>> 0; bb = rol32(bb ^ c, 7);
    }
    return { vote: pc32(a ^ bb ^ c ^ d) & 1, weight: 2.5 };
  }},
  { name: 'SALSA-QR', fn: hex => {
    const b = hexBytes(hex);
    let x0 = 0, x1 = 0, x2 = 0, x3 = 0;
    for (let i = 0; i < 4; i++) x0 = ((x0 << 8) | b[i]) >>> 0;
    for (let i = 4; i < 8; i++) x1 = ((x1 << 8) | b[i]) >>> 0;
    for (let i = 8; i < 12; i++) x2 = ((x2 << 8) | b[i]) >>> 0;
    for (let i = 12; i < 16; i++) x3 = ((x3 << 8) | b[i]) >>> 0;
    x1 ^= rol32((x0 + x3) >>> 0, 7);
    x2 ^= rol32((x1 + x0) >>> 0, 9);
    x3 ^= rol32((x2 + x1) >>> 0, 13);
    x0 ^= rol32((x3 + x2) >>> 0, 18);
    return { vote: pc32(x0 ^ x1 ^ x2 ^ x3) & 1, weight: 2.3 };
  }},
  { name: 'BLAKE-G', fn: hex => {
    const b = hexBytes(hex);
    const v = new Array(16).fill(0);
    for (let i = 0; i < 16; i++) v[i] = b[i] * 0x01010101;
    const G = (a, bb, c, d, x, y) => {
      v[a] = (v[a] + v[bb] + x) >>> 0;
      v[d] = ror32(v[d] ^ v[a], 16);
      v[c] = (v[c] + v[d]) >>> 0;
      v[bb] = ror32(v[bb] ^ v[c], 12);
      v[a] = (v[a] + v[bb] + y) >>> 0;
      v[d] = ror32(v[d] ^ v[a], 8);
      v[c] = (v[c] + v[d]) >>> 0;
      v[bb] = ror32(v[bb] ^ v[c], 7);
    };
    for (let r = 0; r < 4; r++){
      G(0, 4, 8, 12, b[(0+r)%16] * 0x1010101, b[(1+r)%16] * 0x1010101);
      G(1, 5, 9, 13, b[(2+r)%16] * 0x1010101, b[(3+r)%16] * 0x1010101);
      G(2, 6, 10, 14, b[(4+r)%16] * 0x1010101, b[(5+r)%16] * 0x1010101);
      G(3, 7, 11, 15, b[(6+r)%16] * 0x1010101, b[(7+r)%16] * 0x1010101);
    }
    let x = 0;
    for (let i = 0; i < 16; i++) x ^= v[i];
    return { vote: pc32(x) & 1, weight: 2.4 };
  }},
  { name: 'SPECK-MIX', fn: hex => {
    const b = hexBytes(hex); let x = 0, y = 0;
    for (let i = 0; i < 8; i++) x = ((x << 8) | b[i]) >>> 0;
    for (let i = 8; i < 16; i++) y = ((y << 8) | b[i]) >>> 0;
    for (let r = 0; r < 4; r++){
      x = (ror32(x, 8) + y) >>> 0;
      x = (x ^ (r + 1)) >>> 0;
      y = (rol32(y, 3) ^ x) >>> 0;
    }
    return { vote: pc32(x ^ y) & 1, weight: 2.2 };
  }},
  { name: 'MD5-ROUND', fn: hex => {
    const b = hexBytes(hex);
    let a = 0x67452301, c = 0x98badcfe;
    for (let i = 0; i < 16; i += 4){
      const m = (b[i] << 24) | (b[i+1] << 16) | (b[i+2] << 8) | b[i+3];
      const f = ((a & c) | (~a & 0xefcdab89)) >>> 0;
      const t = (f + m) >>> 0;
      a = rol32(a + t, 7) >>> 0;
      c = rol32(c + m, 12) >>> 0;
    }
    return { vote: pc32(a ^ c) & 1, weight: 2.4 };
  }},
  { name: 'KECCAK-THETA', fn: hex => {
    const b = hexBytes(hex);
    const lanes = new Array(5).fill(0);
    for (let i = 0; i < 16; i++) lanes[i % 5] ^= b[i] << ((i % 4) * 8);
    const col = [0,0,0,0,0];
    for (let x = 0; x < 5; x++) col[x] = lanes[x] ^ lanes[(x+1)%5] ^ lanes[(x+2)%5];
    let acc = 0;
    for (let x = 0; x < 5; x++) acc ^= rol32(col[x], 1) >>> 0;
    return { vote: pc32(acc) & 1, weight: 2.3 };
  }},
  { name: 'SHA-SIGMA0', fn: hex => {
    const b = hexBytes(hex); let x = 0;
    for (let i = 0; i < 4; i++) x = ((x << 8) | b[i]) >>> 0;
    const s = (ror32(x, 7) ^ ror32(x, 18) ^ (x >>> 3)) >>> 0;
    return { vote: pc32(s) & 1, weight: 2.3 };
  }},
  { name: 'SHA-SIGMA1', fn: hex => {
    const b = hexBytes(hex); let x = 0;
    for (let i = 4; i < 8; i++) x = ((x << 8) | b[i]) >>> 0;
    const s = (ror32(x, 17) ^ ror32(x, 19) ^ (x >>> 10)) >>> 0;
    return { vote: pc32(s) & 1, weight: 2.3 };
  }},
  { name: 'RIPEMD-MIX', fn: hex => {
    const b = hexBytes(hex);
    let h0 = 0x67452301, h1 = 0xefcdab89;
    for (let i = 0; i < 16; i++){
      const w = b[i] * 0x01010101;
      h0 = rol32((h0 + (h1 ^ w)) >>> 0, 5);
      h1 = rol32((h1 + h0) >>> 0, 7);
    }
    return { vote: pc32(h0 ^ h1) & 1, weight: 2.3 };
  }},
  { name: 'WHIRLPOOL', fn: hex => {
    const b = hexBytes(hex);
    const st = new Uint8Array(16);
    for (let i = 0; i < 16; i++) st[i] = SBOX[b[i] ^ b[(i+1)%16]];
    for (let r = 0; r < 3; r++){
      for (let i = 0; i < 16; i++) st[i] = SBOX[st[i] ^ st[(i+5)%16]];
    }
    let s = 0;
    for (let i = 0; i < 16; i++) s = (s + st[i]) & 0xFF;
    return { vote: pc32(s) & 1, weight: 2.2 };
  }},
  { name: 'THREEFISH', fn: hex => {
    const b = hexBytes(hex);
    let v0 = 0, v1 = 0, v2 = 0, v3 = 0;
    for (let i = 0; i < 4; i++) v0 = ((v0 << 8) | b[i]) >>> 0;
    for (let i = 4; i < 8; i++) v1 = ((v1 << 8) | b[i]) >>> 0;
    for (let i = 8; i < 12; i++) v2 = ((v2 << 8) | b[i]) >>> 0;
    for (let i = 12; i < 16; i++) v3 = ((v3 << 8) | b[i]) >>> 0;
    for (let r = 0; r < 4; r++){
      v0 = (v0 + v1) >>> 0;
      v1 = rol32(v1, 14 + r) >>> 0;
      v1 ^= v0;
      v2 = (v2 + v3) >>> 0;
      v3 = rol32(v3, 16 - r) >>> 0;
      v3 ^= v2;
    }
    return { vote: pc32(v0 ^ v1 ^ v2 ^ v3) & 1, weight: 2.2 };
  }},
  { name: 'TWOFISH-MDS', fn: hex => {
    const b = hexBytes(hex);
    const gf = (a, c) => {
      let r = 0;
      for (let i = 0; i < 8; i++){
        if (c & 1) r ^= a;
        const hi = a & 0x80;
        a = (a << 1) & 0xFF;
        if (hi) a ^= 0x1b;
        c >>= 1;
      }
      return r;
    };
    const MDS = [0x01, 0xEF, 0x5B, 0x5B];
    let acc = 0;
    for (let i = 0; i < 16; i++) acc ^= gf(MDS[i % 4], SBOX[b[i]]);
    return { vote: pc32(acc) & 1, weight: 2.2 };
  }},
  { name: 'XTEA-STEP', fn: hex => {
    const b = hexBytes(hex);
    let v0 = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    let v1 = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7];
    let sum = 0;
    const delta = 0x9E3779B9;
    for (let i = 0; i < 8; i++){
      v0 = (v0 + ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + b[i % 16]))) >>> 0;
      sum = (sum + delta) >>> 0;
      v1 = (v1 + ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + b[(i + 8) % 16]))) >>> 0;
    }
    return { vote: pc32(v0 ^ v1) & 1, weight: 2.3 };
  }},
  { name: 'RC5-MIX', fn: hex => {
    const b = hexBytes(hex);
    let a = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    let c = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7];
    for (let i = 0; i < 6; i++){
      a = (rol32(a ^ c, c & 31) + b[(i*2) % 16]) >>> 0;
      c = (rol32(c ^ a, a & 31) + b[(i*2 + 1) % 16]) >>> 0;
    }
    return { vote: pc32(a ^ c) & 1, weight: 2.2 };
  }},
  { name: 'RC6-CORE', fn: hex => {
    const b = hexBytes(hex);
    let a = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    let c = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7];
    let d = (b[8] << 24) | (b[9] << 16) | (b[10] << 8) | b[11];
    let e = (b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15];
    for (let r = 0; r < 3; r++){
      const t = rol32(Math.imul(c, 2 * c + 1) >>> 0, 5) >>> 0;
      const u = rol32(Math.imul(e, 2 * e + 1) >>> 0, 5) >>> 0;
      a = (rol32(a ^ t, u & 31) + b[r * 4]) >>> 0;
      c = (rol32(c ^ u, t & 31) + b[r * 4 + 1]) >>> 0;
    }
    return { vote: pc32(a ^ c ^ d ^ e) & 1, weight: 2.3 };
  }},
  { name: 'BLAKE2S-G', fn: hex => {
    const b = hexBytes(hex);
    const v = new Array(16);
    for (let i = 0; i < 16; i++) v[i] = (b[i] * 0x01010101) ^ 0x6a09e667;
    const G = (a, bb, c, d, x, y) => {
      v[a] = (v[a] + v[bb] + x) >>> 0;
      v[d] = ror32(v[d] ^ v[a], 16);
      v[c] = (v[c] + v[d]) >>> 0;
      v[bb] = ror32(v[bb] ^ v[c], 12);
      v[a] = (v[a] + v[bb] + y) >>> 0;
      v[d] = ror32(v[d] ^ v[a], 8);
      v[c] = (v[c] + v[d]) >>> 0;
      v[bb] = ror32(v[bb] ^ v[c], 7);
    };
    for (let r = 0; r < 3; r++){
      G(0, 4, 8, 12, b[(0 + r) % 16], b[(1 + r) % 16]);
      G(1, 5, 9, 13, b[(2 + r) % 16], b[(3 + r) % 16]);
      G(2, 6, 10, 14, b[(4 + r) % 16], b[(5 + r) % 16]);
      G(3, 7, 11, 15, b[(6 + r) % 16], b[(7 + r) % 16]);
    }
    let x = 0;
    for (let i = 0; i < 16; i++) x ^= v[i];
    return { vote: pc32(x) & 1, weight: 2.3 };
  }},
  { name: 'GOST-MIX', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let r = 0; r < 4; r++){
      for (let i = 0; i < 16; i++){
        acc = (acc + SBOX[(b[i] + r) % 256]) & 0xFFFF;
        acc = rol32(acc, 1) & 0xFFFF;
      }
    }
    return { vote: pc32(acc) & 1, weight: 2.1 };
  }},
  { name: 'CAMELLIA', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let i = 0; i < 16; i++) s ^= SBOX[b[i] ^ SBOX[b[(i+5) % 16]]];
    for (let i = 0; i < 8; i++) s = (s + SBOX[s & 0xFF]) & 0xFF;
    return { vote: pc32(s) & 1, weight: 2.2 };
  }},
  { name: 'ARIA-SL1', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let i = 0; i < 16; i++){
      const x = b[i];
      s ^= SBOX[x >> 4] ^ ((SBOX[x & 0xF] << 4) & 0xFF);
    }
    return { vote: pc32(s) & 1, weight: 2.2 };
  }},
  { name: 'PRESENT-SL', fn: hex => {
    const b = hexBytes(hex);
    const S = [0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2];
    let s = 0;
    for (let i = 0; i < 16; i++){
      s = ((s << 4) | S[b[i] >> 4]) & 0xFFFF;
      s = ((s << 4) | S[b[i] & 0xF]) & 0xFFFF;
    }
    return { vote: pc32(s) & 1, weight: 2.2 };
  }},
  { name: 'SIMON-MIX', fn: hex => {
    const b = hexBytes(hex); let x = 0, y = 0;
    for (let i = 0; i < 8; i++) x = ((x << 8) | b[i]) >>> 0;
    for (let i = 8; i < 16; i++) y = ((y << 8) | b[i]) >>> 0;
    for (let r = 0; r < 5; r++){
      const t = x;
      x = (y ^ rol32(x, 1) ^ (rol32(x, 8) & rol32(x, 2))) >>> 0;
      y = t;
    }
    return { vote: pc32(x ^ y) & 1, weight: 2.2 };
  }},
  { name: 'HIGHT-MIX', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let r = 0; r < 4; r++){
      s ^= b[(r * 4) % 16] ^ rol32(b[(r * 4 + 1) % 16], 1) ^ rol32(b[(r * 4 + 2) % 16], 2);
      s &= 0xFFFF;
    }
    return { vote: pc32(s) & 1, weight: 2.1 };
  }},
  { name: 'LEA-MIX', fn: hex => {
    const b = hexBytes(hex); let a = 0, c = 0;
    for (let i = 0; i < 16; i += 4){
      a ^= rol32(b[i] | (b[i+1] << 8), 3) + rol32(b[i+2] | (b[i+3] << 8), 5);
      c ^= rol32(b[i] | (b[i+1] << 8), 7) + rol32(b[i+2] | (b[i+3] << 8), 11);
    }
    return { vote: pc32(a ^ c) & 1, weight: 2.2 };
  }},
  { name: 'KASUMI', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let r = 0; r < 4; r++){
      const l = (b[r * 4] << 24) | (b[r * 4 + 1] << 16) | (b[r * 4 + 2] << 8) | b[r * 4 + 3];
      s ^= rol32(l ^ (l >>> 7), r + 1);
    }
    return { vote: pc32(s) & 1, weight: 2.2 };
  }},
  { name: 'MISTY', fn: hex => {
    const b = hexBytes(hex);
    const S9 = [0x1C3, 0x0CB, 0x153, 0x19F, 0x1E3];
    let x = 0, y = 0;
    for (let i = 0; i < 8; i++) x = ((x << 8) | b[i]) >>> 0;
    for (let i = 8; i < 16; i++) y = ((y << 8) | b[i]) >>> 0;
    for (let r = 0; r < 3; r++){
      const t = x;
      x = (y ^ S9[x & 4] ^ (x & 0xFFFF)) >>> 0;
      y = t;
    }
    return { vote: pc32(x ^ y) & 1, weight: 2.2 };
  }},
  { name: 'IDEA-MIX', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let i = 0; i < 16; i += 4){
      const a = (b[i] << 8) | b[i+1];
      const c = (b[i+2] << 8) | b[i+3];
      s ^= (a * c + 1) & 0xFFFF;
      s ^= (a + c) & 0xFFFF;
    }
    return { vote: pc32(s) & 1, weight: 2.1 };
  }},
  { name: 'SAFER-MIX', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let r = 0; r < 3; r++){
      for (let i = 0; i < 16; i++){
        s = (s + SBOX[(b[i] + r * 7) & 0xFF]) & 0xFF;
        s = rol32(s, 1) & 0xFF;
      }
    }
    return { vote: pc32(s) & 1, weight: 2.1 };
  }},
  { name: 'NOEKEON', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let i = 0; i < 16; i++) s ^= b[i];
    for (let r = 0; r < 4; r++){
      s = (s + SBOX[s & 0xFF]) & 0xFFFF;
      s = rol32(s, 5) & 0xFFFF;
    }
    return { vote: pc32(s) & 1, weight: 2.2 };
  }},
  { name: 'CLEFIA', fn: hex => {
    const b = hexBytes(hex); let a = 0, c = 0;
    for (let i = 0; i < 16; i++){ if (i % 2) c ^= SBOX[b[i]]; else a ^= SBOX[b[i]]; }
    for (let r = 0; r < 3; r++){ const t = a; a = (c ^ rol32(a, 2)) >>> 0; c = t; }
    return { vote: pc32(a ^ c) & 1, weight: 2.2 };
  }},
  { name: 'MAGMA-G', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let i = 0; i < 16; i++) s = (s + SBOX[(b[i] + 128) % 256]) & 0xFFFFFF;
    s ^= rol32(s, 11);
    return { vote: pc32(s) & 1, weight: 2.2 };
  }},
  { name: 'KUZNYECHIK', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let r = 0; r < 4; r++){
      for (let i = 0; i < 16; i++) s = ((s << 1) ^ SBOX[b[(i + r) % 16]]) & 0xFFFF;
    }
    return { vote: pc32(s) & 1, weight: 2.2 };
  }},
  { name: 'SHACAL-MIX', fn: hex => {
    const b = hexBytes(hex);
    let a = 0x6a09e667, c = 0xbb67ae85, d = 0x3c6ef372;
    for (let i = 0; i < 16; i++){
      const t = (b[i] * 0x01010101) >>> 0;
      const t1 = (d + (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) + ((a & c) ^ (a & d) ^ (c & d)) + t) >>> 0;
      d = c; c = a; a = t1;
    }
    return { vote: pc32(a ^ c ^ d) & 1, weight: 2.3 };
  }},

  /* ─── MATH FAMILY (63-78) ─── */
  { name: 'PRIME-TEST', fn: hex => {
    const n = BigInt('0x' + hex);
    let r = 1n, base = 2n, e = (n - 1n) / 2n, m = n;
    while (e > 0n){
      if (e & 1n) r = (r * base) % m;
      e >>= 1n;
      base = (base * base) % m;
    }
    return { vote: pcBig(r) & 1, weight: 2.0 };
  }},
  { name: 'MOD-SQUARE', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let i = 0; i < 16; i++) acc = (acc + ((b[i] * b[i]) & 0xFF)) & 0xFFFF;
    return { vote: pc32(acc) & 1, weight: 1.8 };
  }},
  { name: 'GCD-CHAIN', fn: hex => {
    const b = hexBytes(hex);
    const gcd = (a, c) => { while (c){ [a, c] = [c, a % c]; } return a; };
    let acc = b[0] + 1;
    for (let i = 1; i < 16; i++) acc = gcd(acc + b[i], 255);
    return { vote: pc32(acc) & 1, weight: 1.7 };
  }},
  { name: 'COLLATZ', fn: hex => {
    const b = hexBytes(hex); let n = 0;
    for (let i = 0; i < 8; i++) n = ((n << 8) | b[i]) >>> 0;
    let steps = 0;
    for (let i = 0; i < 50 && n !== 1; i++){
      if (n & 1) n = (3 * n + 1) >>> 0;
      else n = (n >>> 1) >>> 0;
      steps++;
    }
    return { vote: pc32(steps + n) & 1, weight: 1.9 };
  }},
  { name: 'DIGITAL-ROOT', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let i = 0; i < 16; i++) s += b[i];
    while (s >= 10) s = Math.floor(s / 10) + (s % 10);
    return { vote: s & 1, weight: 1.6 };
  }},
  { name: 'LEGENDRE', fn: hex => {
    const b = hexBytes(hex); let pos = 0;
    const p = 251;
    for (let i = 0; i < 16; i++){
      const x = b[i] % p;
      if (x === 0) continue;
      let r = 1;
      for (let j = 0; j < (p - 1) / 2; j++) r = (r * x) % p;
      pos += r === 1 ? 1 : 0;
    }
    return { vote: pos & 1, weight: 1.8 };
  }},
  { name: 'FIBONACCI', fn: hex => {
    const b = hexBytes(hex);
    const fibs = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233];
    let hits = 0;
    for (let i = 0; i < 16; i++) if (fibs.includes(b[i])) hits++;
    return { vote: hits & 1, weight: 1.5 };
  }},
  { name: 'PERMUTATION', fn: hex => {
    const b = hexBytes(hex);
    const perm = [7, 2, 11, 4, 15, 8, 1, 14, 5, 12, 3, 10, 0, 13, 6, 9];
    let acc = 0;
    for (let i = 0; i < 16; i++) acc = (acc * 31 + b[perm[i]]) >>> 0;
    return { vote: pc32(acc) & 1, weight: 2.0 };
  }},
  { name: 'MATRIX-TRACE', fn: hex => {
    const b = hexBytes(hex); let trace = 0;
    for (let i = 0; i < 4; i++) trace += b[i*4 + i];
    return { vote: trace & 1, weight: 1.7 };
  }},
  { name: 'MATRIX-DET', fn: hex => {
    const b = hexBytes(hex); let det = 0;
    for (let i = 0; i < 4; i += 2){
      for (let j = 0; j < 4; j += 2){
        det ^= (b[i*4 + j] * b[(i+1)*4 + j+1] - b[i*4 + j+1] * b[(i+1)*4 + j]) & 0xFF;
      }
    }
    return { vote: pc32(det) & 1, weight: 1.9 };
  }},
  { name: 'HARMONIC', fn: hex => {
    const b = hexBytes(hex); let s = 0;
    for (let i = 0; i < 16; i++) s += 1 / (b[i] + 1);
    s = Math.floor(s * 1000) & 0xFFFF;
    return { vote: pc32(s) & 1, weight: 1.7 };
  }},
  { name: 'FRACTAL-CHK', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let i = 0; i < 16; i++){
      acc = (acc + b[i]) & 0xFF;
      acc = (acc ^ (acc >> 3)) & 0xFF;
    }
    return { vote: pc32(acc) & 1, weight: 1.8 };
  }},
  { name: 'MANDELBROT', fn: hex => {
    const b = hexBytes(hex);
    const cr = (b[0] << 8 | b[1]) / 65536 * 4 - 2;
    const ci = (b[2] << 8 | b[3]) / 65536 * 4 - 2;
    let zr = 0, zi = 0, iter = 0;
    while (zr * zr + zi * zi < 4 && iter < 30){
      const t = zr * zr - zi * zi + cr;
      zi = 2 * zr * zi + ci;
      zr = t;
      iter++;
    }
    return { vote: iter & 1, weight: 1.9 };
  }},
  { name: 'LOGISTIC-MAP', fn: hex => {
    const b = hexBytes(hex);
    let x = (b[0] << 8 | b[1]) / 65536;
    const r = 3.9;
    for (let i = 0; i < 20; i++) x = r * x * (1 - x);
    return { vote: Math.floor(x * 65536) & 1, weight: 1.9 };
  }},
  { name: 'CHAOS-LORENZ', fn: hex => {
    const b = hexBytes(hex);
    let x = (b[0] << 8 | b[1]) / 65536 * 20 - 10;
    let y = (b[2] << 8 | b[3]) / 65536 * 20 - 10;
    let z = (b[4] << 8 | b[5]) / 65536 * 20 + 5;
    const sigma = 10, rho = 28, beta = 8/3;
    for (let i = 0; i < 100; i++){
      const dx = sigma * (y - x);
      const dy = x * (rho - z) - y;
      const dz = x * y - beta * z;
      x += dx * 0.01; y += dy * 0.01; z += dz * 0.01;
    }
    return { vote: Math.floor(Math.abs(z) * 100) & 1, weight: 1.9 };
  }},
  { name: 'CANTOR-PAIR', fn: hex => {
    const b = hexBytes(hex); let acc = 0;
    for (let i = 0; i < 16; i += 2){
      const x = b[i], y = b[i+1];
      acc ^= ((x + y) * (x + y + 1) / 2 + y) & 0xFFFF;
    }
    return { vote: pc32(acc) & 1, weight: 1.8 };
  }}
];

/* ═══════════════════════════════════════════════════════
   PREDICTION ENGINE
   ═══════════════════════════════════════════════════════ */
function predict(md5) {
  let taiScore = 0, xiuScore = 0;
  let taiCount = 0, xiuCount = 0;

  for (const alg of ALGOS) {
    let result;
    try { result = alg.fn(md5); }
    catch (e) { result = { vote: 0, weight: 1 }; }
    const w = result.weight || 1;
    if (result.vote === 1) { taiScore += w; taiCount++; }
    else { xiuScore += w; xiuCount++; }
  }

  const total    = taiScore + xiuScore;
  const verdict  = taiScore > xiuScore ? 'TÀI' : (xiuScore > taiScore ? 'XỈU' : 'TÀI');
  const winning  = Math.max(taiScore, xiuScore);
  const losing   = Math.min(taiScore, xiuScore);
  const margin   = (winning - losing) / total;
  const confidence = Math.min(0.97, 0.5 + margin * 0.62);
  const balance  = Math.abs(taiCount - xiuCount);

  return {
    verdict,
    confidence,
    taiCount,
    xiuCount,
    balance,
    totalAlgos: ALGOS.length
  };
}

/* ═══════════════════════════════════════════════════════
   HISTORY PERSISTENCE
   ═══════════════════════════════════════════════════════ */
let predictions = new Map(); // sessionId -> record
let scanCount = 0;

function loadHistory() {
  try {
    if (fs.existsSync(HISTORY_FILE)) {
      const arr = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
      predictions = new Map(arr);
      // prune to last 500
      if (predictions.size > 500) {
        const sorted = Array.from(predictions.entries())
          .sort((a, b) => b[0] - a[0]).slice(0, 500);
        predictions = new Map(sorted);
      }
      console.log(`📚 Loaded ${predictions.size} predictions from history`);
    }
  } catch (e) { console.error('Load history failed:', e.message); }
}

function saveHistory() {
  try {
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(Array.from(predictions.entries())));
  } catch (e) { console.error('Save history failed:', e.message); }
}

loadHistory();

/* ═══════════════════════════════════════════════════════
   RESULT PARSING
   ═══════════════════════════════════════════════════════ */
function resultFromMd5Raw(md5Raw) {
  if (!md5Raw) return null;
  const m = md5Raw.match(/\{(\d+)-(\d+)-(\d+)\}/);
  if (!m) return null;
  const sum = parseInt(m[1]) + parseInt(m[2]) + parseInt(m[3]);
  if (sum === 3 || sum === 18) return 'BÃO';
  return sum >= 11 ? 'TÀI' : 'XỈU';
}

/* ═══════════════════════════════════════════════════════
   SOURCE API FETCH + CACHE
   ═══════════════════════════════════════════════════════ */
let cache = { data: null, ts: 0 };

async function fetchSource(force = false) {
  const now = Date.now();
  if (!force && cache.data && (now - cache.ts) < CACHE_TTL) return cache.data;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
  try {
    const r = await fetch(SOURCE_API, { signal: ctrl.signal });
    if (!r.ok) throw new Error(`Source HTTP ${r.status}`);
    const json = await r.json();
    if (!json || !json.success || !json.data) throw new Error('Invalid source payload');
    cache = { data: json, ts: now };
    return json;
  } finally { clearTimeout(timer); }
}

/* ═══════════════════════════════════════════════════════
   CORE LOGIC: settle + predict
   ═══════════════════════════════════════════════════════ */
function settlePredictions(data) {
  let changed = false;
  for (const key of ['previousSession', 'currentSession']) {
    const s = data[key];
    if (!s || !s.md5Raw) continue;
    const rec = predictions.get(s.id);
    if (!rec || rec.ketQua) continue;
    const actual = resultFromMd5Raw(s.md5Raw);
    if (!actual) continue;
    rec.actual = actual;
    if (actual === 'BÃO') {
      rec.ketQua = '➖ HÒA (BÃO)';
    } else {
      rec.ketQua = rec.prediction === actual ? '✅ ĐÚNG' : '❌ SAI';
    }
    changed = true;
  }
  if (changed) saveHistory();
}

function buildPrediction(data, force = false) {
  const next = data.nextSession;
  if (!next || !next.id || !next.md5Game) {
    return { error: 'nextSession invalid', data };
  }

  const sessionId = next.id;
  const md5       = String(next.md5Game).toLowerCase();

  // Nếu đã có prediction cho phiên này → trả lại
  if (!force && predictions.has(sessionId)) {
    return predictions.get(sessionId);
  }

  const res = predict(md5);

  const record = {
    id: sessionId,
    prediction: res.verdict,
    confidence: Math.round(res.confidence * 100),
    balance: res.balance,
    taiCount: res.taiCount,
    xiuCount: res.xiuCount,
    totalAlgos: res.totalAlgos,
    md5,
    timestamp: new Date().toISOString(),
    actual: null,
    ketQua: null,
    skipped: res.balance < MIN_BALANCE
  };

  predictions.set(sessionId, record);
  saveHistory();
  return record;
}

/* ═══════════════════════════════════════════════════════
   FORMATTER
   ═══════════════════════════════════════════════════════ */
const titleCase = v => v === 'TÀI' ? 'Tài' : v === 'XỈU' ? 'Xỉu' : 'Bỏ qua';

function toApiFormat(rec) {
  if (rec.skipped) {
    return {
      Phien: rec.id,
      Du_doan: 'BỎ QUA',
      Do_tin_cay: '0%',
      Ly_do: `Balance ${rec.balance} < ${MIN_BALANCE} (không đủ tin cậy)`,
      ADMIN,
      ...(rec.ketQua ? { KetQua: rec.ketQua } : {})
    };
  }
  const out = {
    Phien: rec.id,
    Du_doan: titleCase(rec.prediction),
    Do_tin_cay: rec.confidence + '%',
    ADMIN
  };
  if (rec.ketQua) out.KetQua = rec.ketQua;
  return out;
}

/* ═══════════════════════════════════════════════════════
   ROUTES
   ═══════════════════════════════════════════════════════ */
app.get('/', (req, res) => {
  res.type('text/plain').send(
`╔══════════════════════════════════════════════╗
║   AURORA ORACLE · SUPREME API v4             ║
║   ${ALGOS.length} algorithms · parity voting              ║
║   ADMIN: ${ADMIN}                          ║
╚══════════════════════════════════════════════╝

ENDPOINTS
  GET /api/predict          → dự đoán phiên kế tiếp
  GET /api/predict?force=1  → bỏ cache, chạy lại
  GET /api/history          → lịch sử (kèm KetQua nếu đã có)
  GET /api/history?limit=20 → N kết quả gần nhất
  GET /health               → trạng thái server
  GET /api/debug            → thông tin raw từ source

RULES
  • Balance < ${MIN_BALANCE}  → BỎ QUA (không dự đoán)
  • Confidence = 50% + margin×0.62 (cap 97%)
  • KetQua = ✅ ĐÚNG / ❌ SAI / ➖ HÒA (BÃO)
`);
});

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    uptime: process.uptime(),
    scans: scanCount,
    predictions: predictions.size,
    algorithms: ALGOS.length,
    admin: ADMIN
  });
});

app.get('/api/predict', async (req, res) => {
  try {
    const force = req.query.force === '1' || req.query.force === 'true';
    scanCount++;

    const src = await fetchSource(force);
    const data = src.data;

    settlePredictions(data);
    const rec = buildPrediction(data, force);

    if (rec.error) return res.status(500).json({ success: false, error: rec.error });

    res.json(toApiFormat(rec));
  } catch (e) {
    console.error('[predict]', e);
    res.status(500).json({
      success: false,
      error: 'Không thể lấy dữ liệu từ API gốc',
      detail: e.message
    });
  }
});

app.get('/api/history', (req, res) => {
  const limit = Math.max(1, Math.min(500, parseInt(req.query.limit) || 50));

  const arr = Array.from(predictions.values())
    .sort((a, b) => a.id - b.id)
    .slice(-limit)
    .map(toApiFormat);

  res.json(arr);
});

app.get('/api/debug', async (req, res) => {
  try {
    const src = await fetchSource(req.query.force === '1');
    res.json({
      success: true,
      source: SOURCE_API,
      nextSessionId: src.data.nextSession?.id,
      currentSessionId: src.data.currentSession?.id,
      previousSessionId: src.data.previousSession?.id,
      raw: src.data
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/* ═══════════════════════════════════════════════════════
   SERVER START
   ═══════════════════════════════════════════════════════ */
app.listen(PORT, () => {
  console.log(`\n🚀 Aurora Oracle API listening on :${PORT}`);
  console.log(`📡 Source: ${SOURCE_API}`);
  console.log(`⚙️  ${ALGOS.length} algorithms loaded`);
  console.log(`👑 ADMIN: ${ADMIN}\n`);
});