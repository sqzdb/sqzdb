#!/bin/sh
# Install the main package and one platform package from their tarballs into an empty project, as a user would, and
# use it: sh smoke.sh <sqzdb-x.y.z.tgz> <sqzdb-<platform>-x.y.z.tgz>
set -e
main=$(realpath "$1"); plat=$(realpath "$2"); dir=$(mktemp -d)
cd "$dir" && npm init -y >/dev/null && npm install --no-audit --no-fund --loglevel=error "$plat" "$main" >/dev/null
node -e "
const { open } = require('sqzdb');
const db = open('$dir/data');
db.exec('CREATE TABLE notes (id SERIAL PRIMARY KEY, body TEXT)');
db.run('INSERT INTO notes (body) VALUES (?)', ['x'.repeat(100000)]);
const r = db.get('SELECT length(body) AS len FROM notes WHERE id = 1');
if (r.len !== 100000) throw new Error('unexpected ' + JSON.stringify(r));
db.close(); console.log('sqzdb from npm: ok on', process.platform, process.arch);
"
rm -rf "$dir"
