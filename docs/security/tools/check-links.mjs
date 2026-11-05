#!/usr/bin/env node
// Check that every relative link and #anchor in docs/security/*.md resolves inside a tree: the
// staged public cut (scripts/ossync-check.sh <stage>), so links that work in the monorepo but not
// in the mirror fail too. Run by eggrd-security-docs.yml in the source repository.
//
//   node check-links.mjs <root>      # <root> is the staged cut (or the module directory)
import fs from 'fs';
import path from 'path';
const root = process.argv[2];
const dir = path.join(root, 'docs/security');
const slug = (h) => h.toLowerCase().replace(/[^a-z0-9 _-]/g, '').trim().replace(/ /g, '-');
const anchorsOf = (f) => {
  const s = fs.readFileSync(f, 'utf8').replace(/```[\s\S]*?```/g, '');
  const a = new Set();
  for (const m of s.matchAll(/^#{1,6} (.+)$/gm)) a.add(slug(m[1]));
  for (const m of s.matchAll(/<a id="([^"]+)"/g)) a.add(m[1]);
  return a;
};
let bad = 0, n = 0;
for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.md'))) {
  const full = path.join(dir, f);
  const s = fs.readFileSync(full, 'utf8').replace(/```[\s\S]*?```/g, '');
  for (const m of s.matchAll(/\]\(([^)\s]+)\)/g)) {
    const href = m[1];
    if (/^https?:/.test(href)) continue;
    n++;
    const [p, frag] = href.split('#');
    const target = p ? path.resolve(dir, p) : full;
    if (!fs.existsSync(target)) { bad++; console.log('MISSING', f, href); continue; }
    if (frag && target.endsWith('.md') && !anchorsOf(target).has(frag)) { bad++; console.log('NO ANCHOR', f, href); }
  }
}
console.log(`${n} relative links, ${bad} broken`);
process.exit(bad ? 1 : 0);
