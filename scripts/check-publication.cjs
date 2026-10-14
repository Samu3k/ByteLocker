#!/usr/bin/env node
'use strict';
// Deliberately prints rule names and paths only, never matching values.
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

function inspect(name, bytes) {
  const findings = [];
  const file = name.replaceAll('\\', '/');
  const base = path.posix.basename(file);
  if (/(^|\/)(data|secrets|backups|build|dist|releases|\.git|\.dart_tool|\.gradle|\.cxx|ephemeral)(\/|$)/i.test(file) ||
      (/^\.env(?:\..*)?$/.test(base) && base !== '.env.example') ||
      /^(instance\.keys|local\.properties|key\.properties|credentials\.json|\.netrc|\.npmrc|\.pypirc|id_rsa.*|id_ed25519.*)$/i.test(base) ||
      /\.(db(?:-wal|-shm|-journal)?|sqlite3?|keystore|jks|pem|key|p12|pfx|apk|aab|exe|dll|pdb|zip|idsig|iml|log)$/i.test(base) ||
      /\.tar(?:\.gz)?$/i.test(base) || /(^|\/)\.bytelocker-(?:snapshot|backup)-/.test(file)) {
    findings.push('private-or-generated-file');
  }
  if (/\.(png|ico|webp|jpg|jpeg|ttf|otf)$/i.test(base)) return findings;
  const text = bytes.toString('utf8');
  for (const match of text.matchAll(/https?:\/\/([a-z0-9-]+)\.trycloudflare\.com/gi)) {
    if (!['nome-casuale', 'your-tunnel', 'example', 'tunnel'].includes(match[1].toLowerCase())) findings.push('personal-tunnel-url');
  }
  if (/[A-Z]:[/\\]Users[/\\][^/\\\s]+[/\\]/i.test(text)) findings.push('personal-machine-path');
  if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/.test(text)) findings.push('private-key');
  if (/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AIza[A-Za-z0-9_-]{30,}|AKIA[A-Z0-9]{16})\b/.test(text)) findings.push('credential-pattern');
  if (base === '.env.example' && /^\s*PM_SMTP_USERNAME\s*=\s*\S+/m.test(text)) findings.push('configured-mail-in-example');
  if (/^client\/(lib|android\/app\/src\/main|windows\/runner)\//.test(file) &&
      /https?:\/\/(?:192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/.test(text)) findings.push('private-server-in-client');
  return [...new Set(findings)];
}

function git(args, input) {
  const result = spawnSync(process.env.BYTELOCKER_GIT || 'git', args, {
    input, maxBuffer: 128 * 1024 * 1024, windowsHide: true,
  });
  if (result.status !== 0) throw new Error('Cannot read repository index. Run from the repository root.');
  return result.stdout;
}

function main() {
  const staged = process.argv.includes('--staged');
  const files = git(['ls-files', '-z']).toString('utf8').split('\0').filter(Boolean);
  if (files.length === 0) throw new Error('The index is empty: add the reviewed source files first.');
  if (files.some(file => /[\r\n]/.test(file))) throw new Error('Unsupported filename in repository.');
  let batch, offset = 0;
  if (staged) batch = git(['cat-file', '--batch'], files.map(file => ':' + file).join('\n') + '\n');
  let failed = false;
  for (const file of files) {
    let bytes;
    if (staged) {
      const end = batch.indexOf(10, offset);
      const header = batch.subarray(offset, end).toString('ascii');
      const match = /^[a-f0-9]+ blob (\d+)$/.exec(header);
      if (!match) throw new Error('Non-regular object in source index.');
      const length = Number(match[1]);
      bytes = batch.subarray(end + 1, end + 1 + length);
      offset = end + 1 + length + 1;
    } else {
      const info = fs.lstatSync(file);
      if (!info.isFile() || info.isSymbolicLink()) throw new Error('Non-regular file: ' + file);
      bytes = fs.readFileSync(file);
    }
    for (const rule of inspect(file, bytes)) {
      console.error(`${rule}: ${file}`);
      failed = true;
    }
  }
  if (failed) process.exitCode = 1;
  else console.log(`Publication check passed: ${files.length} source files, ${staged ? 'staged content' : 'working tree'}.`);
}

module.exports = {inspect};
if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
