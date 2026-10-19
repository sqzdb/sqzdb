// Make the npm package that carries the engine for one platform: node npm-platform.mjs <rust target> <built library> <out dir> <version>
// It is one of the main package's optionalDependencies; npm installs the one whose os, cpu and libc match.
import fs from 'node:fs'; import path from 'node:path';
const [target, lib, out, version] = process.argv.slice(2);
const platforms = {
  'x86_64-unknown-linux-gnu': ['linux-x64-gnu', 'linux', 'x64', 'glibc'], 'x86_64-unknown-linux-musl': ['linux-x64-musl', 'linux', 'x64', 'musl'],
  'aarch64-unknown-linux-gnu': ['linux-arm64-gnu', 'linux', 'arm64', 'glibc'], 'aarch64-unknown-linux-musl': ['linux-arm64-musl', 'linux', 'arm64', 'musl'],
  'x86_64-apple-darwin': ['darwin-x64', 'darwin', 'x64', null], 'aarch64-apple-darwin': ['darwin-arm64', 'darwin', 'arm64', null],
};
const p = platforms[target]; if (!p || !lib || !out || !version) { console.error(`usage: npm-platform.mjs <${Object.keys(platforms).join('|')}> <library> <out dir> <version>`); process.exit(2); }
const [suffix, os, cpu, libc] = p; const name = `@sqzdb/${suffix}`; const dir = path.join(out, suffix);
fs.mkdirSync(dir, { recursive: true }); fs.copyFileSync(lib, path.join(dir, 'sqzdb.node'));
const pkg = { name, version, description: `The sqzdb engine for ${os} ${cpu}${libc ? ` (${libc})` : ''}: installed with the sqzdb package`, license: 'MIT',
  repository: { type: 'git', url: 'git+https://github.com/sqzdb/sqzdb.git', directory: 'bindings/node' }, main: 'sqzdb.node', files: ['sqzdb.node'],
  os: [os], cpu: [cpu], ...(libc ? { libc: [libc] } : {}), engines: { node: '>=20' } };
fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');
fs.writeFileSync(path.join(dir, 'README.md'), `# ${name}\n\nThe [sqzdb](https://www.npmjs.com/package/sqzdb) engine for ${os} ${cpu}${libc ? ` (${libc})` : ''}. Install \`sqzdb\`, which brings this along.\n`);
console.log(`${name}@${version}: ${dir} (${(fs.statSync(lib).size / 1e6).toFixed(1)} MB)`);
