#!/bin/sh
# Install the main package and one platform package from their tarballs into an empty project, as a user would, and
# use it: sh smoke.sh <sqzdb-x.y.z.tgz> <sqzdb-<platform>-x.y.z.tgz>
set -e
main=$(realpath "$1"); plat=$(realpath "$2"); dir=$(mktemp -d)
cd "$dir" && npm init -y >/dev/null && npm install --no-audit --no-fund --loglevel=error "$plat" "$main" >/dev/null
# a function in TypeScript: the engine strips its types and runs it (and sqzdb/functions resolves in Node too)
mkdir -p "$dir/functions" && printf "import { fn } from 'sqzdb/functions'\nexport const add = fn({ args: { body: 'text' }, run: ({ db }, { body }): number => Number(db.run('INSERT INTO notes (body) VALUES (?)', [body]).lastInsertId) })\n" > "$dir/functions/notes.ts"
node -e "
const { open } = require('sqzdb'); const { fn } = require('sqzdb/functions');
if (typeof fn !== 'function') throw new Error('sqzdb/functions');
const db = open('$dir/data', { functions: '$dir/functions' });
db.exec('CREATE TABLE notes (id SERIAL PRIMARY KEY, body TEXT)');
const id = db.call('add', { body: 'x'.repeat(100000) });
const r = db.get('SELECT length(body) AS len FROM notes WHERE id = ?', [id]);
if (r.len !== 100000) throw new Error('unexpected ' + JSON.stringify(r));
db.close(); console.log('sqzdb from npm: ok on', process.platform, process.arch);
"
rm -rf "$dir"
