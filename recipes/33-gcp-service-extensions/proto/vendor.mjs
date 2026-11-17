// Re-creates the vendored ext_proc schema in this directory from pinned upstream commits. Run only to change the pins:
//   node proto/vendor.mjs
// It starts at the ext_proc service definition, follows every import, and fetches each file byte for byte from the
// commit that Envoy's own API build pins for that dependency. google/protobuf/*.proto are not fetched: protobufjs bundles
// the well-known types and always uses its own copies. It writes SHA256SUMS, which the unit tests check.

import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// Envoy v1.40.2; the others are the versions its api/MODULE.bazel declares.
const SOURCES = [
  { prefixes: ['envoy/'], repo: 'envoyproxy/envoy', commit: 'b2d89e0ae53916f28770771fbdd49c5c99c5c5a2', dir: 'api/' },
  { prefixes: ['xds/', 'udpa/'], repo: 'cncf/xds', commit: 'ee656c7534f5d7dc23d44dd611689568f72017a6', dir: '' },
  { prefixes: ['validate/'], repo: 'bufbuild/protoc-gen-validate', commit: '92b9a7df69ca9f71bfc492f7a90adf4d36eab569', dir: '' },
];
const ROOT = 'envoy/service/ext_proc/v3/external_processor.proto';

const raw = (source, path) => `https://raw.githubusercontent.com/${source.repo}/${source.commit}/${path}`;

async function fetchBytes(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

const files = new Map();
const queue = [ROOT];
while (queue.length > 0) {
  const path = queue.shift();
  if (files.has(path) || path.startsWith('google/protobuf/')) continue;
  const source = SOURCES.find((s) => s.prefixes.some((prefix) => path.startsWith(prefix)));
  if (source === undefined) throw new Error(`no pinned source for ${path}`);
  const bytes = await fetchBytes(raw(source, source.dir + path));
  files.set(path, bytes);
  const text = new TextDecoder().decode(bytes);
  for (const match of text.matchAll(/^import\s+(?:public\s+|weak\s+)?"([^"]+)";/gm)) queue.push(match[1]);
}

for (const source of SOURCES) {
  const name = `LICENSE.${source.repo.split('/')[1]}`;
  files.set(name, await fetchBytes(raw(source, 'LICENSE')));
}

const sums = [];
for (const [path, bytes] of [...files].sort(([a], [b]) => (a < b ? -1 : 1))) {
  await mkdir(dirname(join(here, path)), { recursive: true });
  await writeFile(join(here, path), bytes);
  sums.push(`${createHash('sha256').update(bytes).digest('hex')}  ${path}`);
}
await writeFile(join(here, 'SHA256SUMS'), sums.join('\n') + '\n');
console.log(`${files.size} files written`);
