#!/usr/bin/env node
// Encrypts the plaintext page into payload.enc.json for the password gate in index.html.
// Usage: node tools/encrypt.mjs [source.html]
// The password is read from a hidden prompt (or HRA_PASSWORD), never from the command line,
// so it does not end up in shell history. Nothing about the password is written to disk.
import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes, pbkdf2Sync, createCipheriv } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ITER = 600000;
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const src = resolve(process.argv[2] || resolve(root, 'source.html'));
const out = resolve(root, 'payload.enc.json');

function ask(q) {
  return new Promise((res) => {
    const { stdin, stdout } = process;
    stdout.write(q);
    let buf = '';
    stdin.setRawMode?.(true); stdin.resume(); stdin.setEncoding('utf8');
    const on = (ch) => {
      for (const c of ch) {
        if (c === '\r' || c === '\n') { stdin.setRawMode?.(false); stdin.pause(); stdin.off('data', on); stdout.write('\n'); return res(buf); }
        if (c === '\u0003') { stdout.write('\n'); process.exit(130); }
        if (c === '\u007f' || c === '\b') { buf = buf.slice(0, -1); continue; }
        buf += c;
      }
    };
    stdin.on('data', on);
  });
}

let pw = process.env.HRA_PASSWORD;
if (!pw) {
  pw = await ask('Password for the page: ');
  const again = await ask('Type it again: ');
  if (pw !== again) { console.error('Passwords did not match. Nothing was written.'); process.exit(1); }
}
if (pw.length < 12) console.warn('Warning: short password. Anyone with the payload can guess offline; 16+ characters is better.');

const plain = readFileSync(src);
const salt = randomBytes(16), iv = randomBytes(12);
const key = pbkdf2Sync(pw, salt, ITER, 32, 'sha256');
const c = createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]); // WebCrypto expects ciphertext||tag
writeFileSync(out, JSON.stringify({ v: 1, kdf: 'PBKDF2-SHA256', iter: ITER, cipher: 'AES-256-GCM',
  salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64') }) + '\n');
console.log(`Wrote ${out} (${plain.length} bytes encrypted).`);
