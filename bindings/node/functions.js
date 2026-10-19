// sqzdb/functions: what an app's functions import. Inside the database the engine provides this module; this copy is
// the same, so Node (a test, a type check) can load a function and call its run() with a context of its own.
'use strict';
const MARK = Symbol.for('sqzdb.function');
const mark = (def, kind) => {
  if (def === null || typeof def !== 'object' || typeof def.run !== 'function') throw new TypeError(`${kind === 'function' ? 'fn' : kind}() takes an object with run(ctx, …) { … }`);
  return Object.freeze({ ...def, [MARK]: kind });
};
/** A function clients call by name: `export const reportRun = fn({ args, run(ctx, args) { … } })`. */
const fn = (def) => mark(def, 'function');
/** Runs before requests to the paths it matches go on: return a Response to answer instead. */
const middleware = (def) => mark(def, 'middleware');
/** An endpoint the API answers itself. */
const route = (def) => mark(def, 'route');
/** To the API's sign-in page, and back to this request's page after. */
const signIn = (req, page = '/_sqz/sign-in') => Response.redirect(`${page}?return=${encodeURIComponent(req.url)}`, 302);
module.exports = { fn, middleware, route, signIn, Response: globalThis.Response, Headers: globalThis.Headers };
