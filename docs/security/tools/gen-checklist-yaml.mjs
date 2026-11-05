#!/usr/bin/env node
// Generate checklist.yaml from HARDENING-CHECKLIST.md (the source of truth), so the two cannot
// drift. Run from anywhere:
//
//   node docs/security/tools/gen-checklist-yaml.mjs           # rewrite checklist.yaml
//   node docs/security/tools/gen-checklist-yaml.mjs --check   # exit 1 if checklist.yaml is stale
//
// No dependencies: the YAML is written by hand, with literal block scalars for anything that
// spans lines (the reasoning, multi-line verify commands).
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const md = fs.readFileSync(path.join(dir, 'HARDENING-CHECKLIST.md'), 'utf8').replace(/\r\n/g, '\n');
const out = path.join(dir, 'checklist.yaml');

// The version and image digest come from the documents, never from this script, and must agree:
// README.md names the pinned image, the checklist's intro names the version, and EG-HARD-220 pins
// the same digest. A release bump that misses one of them fails here (and so in CI).
const readme = fs.readFileSync(path.join(dir, 'README.md'), 'utf8');
const imgM = readme.match(/mancube\/eggrd:(\d+\.\d+\.\d+)@(sha256:[0-9a-f]{64})/);
const verM = md.match(/^For eggrd \*\*(\d+\.\d+\.\d+)\*\*/m);
const problems = [];
if (!imgM) problems.push('README.md names no mancube/eggrd:X.Y.Z@sha256:… image');
if (!verM) problems.push('HARDENING-CHECKLIST.md has no "For eggrd **X.Y.Z**" line');
if (imgM && verM && imgM[1] !== verM[1]) problems.push(`README.md pins ${imgM[1]} but the checklist is for ${verM[1]}`);
const e220 = md.split('### EG-HARD-220')[1]?.split('\n### ')[0] ?? '';
if (imgM && !e220.includes(imgM[2])) problems.push(`EG-HARD-220 does not pin the README's digest ${imgM[2]}`);
// One digest per version: a pin of another release (0.7.1 next to 0.7.0, say) is fine, but the same
// version must not appear with two digests, and an untagged pin must be the digest of a named one.
const digests = new Map();
for (const [src, text] of [['README.md', readme], ['HARDENING-CHECKLIST.md', md]]) {
  for (const m of text.matchAll(/mancube\/eggrd:(\d+\.\d+\.\d+[\w.-]*)@(sha256:[0-9a-f]{64})/g)) {
    const seen = digests.get(m[1]);
    if (seen && seen !== m[2]) problems.push(`${src} pins eggrd ${m[1]} at ${m[2]}, elsewhere at ${seen}`);
    else digests.set(m[1], m[2]);
  }
}
const known = new Set(digests.values());
for (const m of md.matchAll(/mancube\/eggrd@(sha256:[0-9a-f]{64})/g)) if (!known.has(m[1])) problems.push(`HARDENING-CHECKLIST.md pins an eggrd digest of no named version: ${m[1]}`);
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
const VERSION = imgM[1];
const IMAGE = `docker.io/mancube/eggrd:${VERSION}@${imgM[2]}`;

// Config tables that are maps (src/config.rs: BTreeMap fields), whose keys are user data.
const MAP_TABLES = new Set(['auth.users', 'llm.models']);
const SETUPS = ['compose-single-vm', 'kubernetes', 'aws-nlb', 'aws-alb', 'hybrid-pools', 'monitoring'];
const q = (s) => JSON.stringify(s); // a JSON string is a valid YAML double-quoted scalar
const block = (text, indent) => {
  const pad = ' '.repeat(indent);
  return '|-\n' + text.split('\n').map((l) => (l.length ? pad + l : '')).join('\n');
};
// GitHub's heading anchor.
const anchor = (h) => h.toLowerCase().replace(/[^a-z0-9 _-]/g, '').trim().replace(/ /g, '-');

function references(line) {
  const refs = [];
  const seen = new Set();
  const add = (k, v) => { const key = k + ':' + v; if (!seen.has(key)) { seen.add(key); refs.push({ [k]: v }); } };
  for (const m of line.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    const target = path.posix.normalize(path.posix.join('docs/security', m[1].split('#')[0]));
    const setup = target.match(/^deploy\/reference\/([^/]+)\/?$/);
    if (setup && SETUPS.includes(setup[1])) add('setup', setup[1]);
    else add('file', target.replace(/\/$/, ''));
  }
  if (/\bevery( TLS)? setup\b/.test(line)) for (const s of SETUPS) if (s !== 'monitoring') add('setup', s);
  return refs;
}

const items = [];
let layer = null;
const lines = md.split('\n');
for (let i = 0; i < lines.length; i++) {
  const lm = lines[i].match(/^## (.+)$/);
  if (lm) { layer = lm[1] === 'Contents' ? null : lm[1]; continue; }
  const im = lines[i].match(/^### (EG-HARD-\d{3}) · (.+)$/);
  if (!im) continue;
  let j = i + 1;
  while (j < lines.length && !/^##/.test(lines[j])) j++;
  const body = lines.slice(i + 1, j).join('\n');
  const metaLine = body.split('\n').find((l) => l.startsWith('**Severity:**')) || '';
  const severity = (metaLine.match(/\*\*Severity:\*\* ([A-Za-z]+)/) || [])[1];
  const tags = [];
  if (metaLine.includes('**[App]**')) tags.push('app');
  if (metaLine.includes('**[0.8]**')) tags.push('workaround-until-0.8');
  if (metaLine.includes('**[Gap]**')) tags.push('gap');
  const refLine = (metaLine.match(/\*\*Reference:\*\* (.+)$/) || [])[1] || '';
  // The reasoning: from **Why.** to the next **Config.** / **Verify.** marker, whole.
  const whyM = body.match(/\*\*Why\.\*\* ([\s\S]*?)(?=\n\*\*(Config|Verify)\.\*\*|$)/);
  const why = whyM ? whyM[1].trim() : '';
  const keys = new Set();
  for (const b of body.matchAll(/```toml\n([\s\S]*?)```/g)) {
    let sec = '';
    for (const t of b[1].split('\n')) {
      const s = t.match(/^\[\[?([\w.]+)\]\]?/);
      if (s) { sec = s[1]; continue; }
      const k = t.match(/^(\w+)\s*=/);
      // A table whose entries are data, not settings (`[auth.users]` maps user names to hashes,
      // `[llm.models]` model names to prices): record the table, not its entries.
      if (k) keys.add(MAP_TABLES.has(sec) ? sec : sec ? sec + '.' + k[1] : k[1]);
    }
  }
  // Verify: every sh block after the **Verify.** marker, each kept whole (continuation lines and
  // loops stay runnable).
  const verify = [];
  const vIdx = body.indexOf('**Verify.**');
  if (vIdx >= 0) for (const b of body.slice(vIdx).matchAll(/```sh\n([\s\S]*?)```/g)) verify.push(b[1].replace(/\n$/, ''));
  items.push({ id: im[1], title: im[2], layer, severity, tags, keys: [...keys], refs: references(refLine), why, verify });
}

let y = '';
y += '# GENERATED by tools/gen-checklist-yaml.mjs from HARDENING-CHECKLIST.md (the source of truth).\n';
y += '# Do not edit by hand: change the markdown and re-run the generator (--check fails on drift).\n';
y += `# eggrd ${VERSION}. Per item: id, title, layer, severity, tags (app | workaround-until-0.8 | gap),\n`;
y += '# the config keys its TOML sets, the reference setups or files that implement it, the reasoning,\n';
y += '# and its verify commands (each a whole shell block).\n';
y += 'version: 2\n';
y += `eggrd: ${q(VERSION)}\n`;
y += `image: ${q(IMAGE)}\n`;
y += 'source: HARDENING-CHECKLIST.md\n';
y += `total: ${items.length}\n`;
const counts = {};
for (const it of items) counts[it.layer] = (counts[it.layer] || 0) + 1;
y += 'counts_by_layer:\n';
for (const [k, v] of Object.entries(counts)) y += `  ${q(k)}: ${v}\n`;
y += 'items:\n';
for (const it of items) {
  y += `  - id: ${it.id}\n`;
  y += `    title: ${q(it.title)}\n`;
  y += `    layer: ${q(it.layer)}\n`;
  y += `    severity: ${it.severity}\n`;
  y += `    tags: [${it.tags.join(', ')}]\n`;
  y += `    keys: [${it.keys.map(q).join(', ')}]\n`;
  y += `    reference: [${it.refs.map((r) => { const [k, v] = Object.entries(r)[0]; return `{${k}: ${q(v)}}`; }).join(', ')}]\n`;
  y += `    anchor: ${q('HARDENING-CHECKLIST.md#' + anchor(it.id + ' · ' + it.title))}\n`;
  y += `    why: ${block(it.why, 6)}\n`;
  if (it.verify.length) {
    y += '    verify:\n';
    for (const v of it.verify) y += `      - ${block(v, 8)}\n`;
  } else y += '    verify: []\n';
}

const bad = items.filter((i) => !i.severity || !i.why || !i.layer);
if (bad.length) { console.error('items missing severity, why or layer:', bad.map((b) => b.id).join(' ')); process.exit(1); }
if (process.argv.includes('--check')) {
  const cur = fs.existsSync(out) ? fs.readFileSync(out, 'utf8').replace(/\r\n/g, '\n') : '';
  if (cur !== y) { console.error('checklist.yaml is out of date: run node docs/security/tools/gen-checklist-yaml.mjs'); process.exit(1); }
  console.log(`checklist.yaml is current (${items.length} items)`);
} else {
  fs.writeFileSync(out, y);
  console.log(`wrote ${out}: ${items.length} items`, JSON.stringify(counts));
}
