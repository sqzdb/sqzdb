/**
 * An app's functions, middleware and routes: modules in the folder the database deploys (`open(dir, { functions: './functions' })`, or
 * `[functions] dir` in the server's config). They run inside the database, one transaction per call, and clients call
 * them by name: `db.call(name, args)`, `POST /api/fn/<name>`, and MCP, where each is a tool.
 *
 *   import { fn } from 'sqzdb/functions'
 *   export const reportRun = fn({
 *     description: 'Report how a run ended',
 *     args: { runId: 'int', status: ['completed', 'failed'], outcome: 'text?' },
 *     roles: ['agent'],
 *     run({ db, admin }, { runId, status, outcome }) { … },
 *   })
 */

/** A value as a function sees it: INT a number (BigInt past 2^53), TIMESTAMP a Date, BYTES a Uint8Array. */
export type Value = number | bigint | string | boolean | Uint8Array | Date | null;
export type Row = Record<string, Value>;
/** An array of values for the `?`s, or one value. Objects and arrays become their JSON text. */
export type Params = readonly unknown[] | Value | Record<string, unknown>;
export interface RunResult { changes: number; lastInsertId?: number | string }

/** SELECT, INSERT, UPDATE and DELETE in the call's transaction (SELECT only in a readOnly function). */
export interface Db {
  get<R extends Row = Row>(sql: string, params?: Params): R | null;
  all<R extends Row = Row>(sql: string, params?: Params): R[];
  run(sql: string, params?: Params): RunResult;
}
export interface Context {
  /** As the caller: their grants and row policies apply. */
  db: Db;
  /** The same transaction without grants or policies: for the rules a caller must not get around. */
  admin: Db;
  /** Who is calling: their row's columns, or the attributes the app vouched for; null when the app itself calls. */
  user: Record<string, Value> | null;
  roles: string[];
}

type Base = 'int' | 'number' | 'text' | 'bool' | 'uuid' | 'json';
/** An argument: a type (with ? when it may be left out), the texts it may be, or the long form. */
export type ArgType = Base | `${Base}?` | readonly string[] | { type?: Base | `${Base}?` | readonly string[]; enum?: readonly string[]; description?: string; optional?: boolean };
type BaseOf<T> = T extends 'int' | 'number' ? number : T extends 'text' | 'uuid' ? string : T extends 'bool' ? boolean : unknown;
type One<A> = A extends readonly (infer E)[] ? E : A extends `${infer B}?` ? BaseOf<B> : A extends { enum: readonly (infer E)[] } ? E : A extends { type: infer T } ? One<T> : BaseOf<A>;
type Optional<A> = A extends `${string}?` ? true : A extends { optional: true } ? true : A extends { type: `${string}?` } ? true : false;
/** The arguments `run` receives, from `args`. */
export type ArgsOf<S extends Record<string, ArgType>> =
  { [K in keyof S as Optional<S[K]> extends true ? never : K]: One<S[K]> } & { [K in keyof S as Optional<S[K]> extends true ? K : never]?: One<S[K]> | null };

export interface Definition<S extends Record<string, ArgType>, R> {
  /** What it does, for the people and agents who call it (MCP shows it). */
  description?: string;
  args?: S;
  /** Who may call it; without roles, anyone signed in (the anonymous role only when listed). */
  roles?: readonly string[];
  /** It only reads: SELECT only, and agents see it as safe to call. */
  readOnly?: boolean;
  /** How your app reaches it over HTTP: POST /api/fn/<name> with the arguments as JSON (the default, and always), or
   *  'GET' to answer GET /api/fn/<name>?arg=value too, the arguments read as `args` say; a GET function only reads. */
  method?: 'GET' | 'POST';
  /** Whether agents get it as an MCP tool (the default); false keeps it off their list. */
  mcp?: boolean;
  /** false: deployed, but reachable from the console's Try panel only, not from the app, agents or the socket (NOT_FOUND). */
  enabled?: boolean;
  /** Its result is any JSON value (a Date becomes its ISO text, BYTES 0x-prefixed hex). Throwing rolls the call back;
   *  an Error with a `code` (UPPER_CASE) gives the caller that code. */
  run(ctx: Context, args: ArgsOf<S>): R | Promise<R>;
}
export function fn<const S extends Record<string, ArgType> = {}, R = unknown>(def: Definition<S, R>): Readonly<Definition<S, R>>;

/** The little of the Fetch API that middleware and routes use; global inside the database as well. */
export declare class Headers implements Iterable<[string, string]> {
  constructor(init?: Record<string, string> | [string, string][] | Headers);
  get(name: string): string | null; has(name: string): boolean; set(name: string, value: string): void; append(name: string, value: string): void; delete(name: string): void;
  getSetCookie(): string[]; entries(): IterableIterator<[string, string]>; keys(): IterableIterator<string>; values(): IterableIterator<string>;
  forEach(f: (value: string, name: string, h: Headers) => void): void; [Symbol.iterator](): IterableIterator<[string, string]>;
}
export declare class Response {
  constructor(body?: string | Uint8Array | ArrayBuffer | null, init?: { status?: number; statusText?: string; headers?: Record<string, string> | [string, string][] | Headers });
  status: number; statusText: string; headers: Headers; body: string | Uint8Array | ArrayBuffer | null; readonly ok: boolean;
  static json(value: unknown, init?: { status?: number; headers?: Record<string, string> | [string, string][] | Headers }): Response;
  static redirect(url: string, status?: number): Response;
}
/** What middleware returns to answer: this module's Response, or the DOM's (in a project with the DOM's types, the
 *  global one is fine; elsewhere import Response from here, which inside the database is the global one). */
export interface ResponseLike { readonly status: number }
/** A request, as middleware and routes get it. */
export interface Request {
  method: string;
  /** As patterns matched it: decoded and normalized (`/adm%69n//x` is `/admin/x`). Check paths with this one. */
  path: string;
  /** As sent. */
  rawPath: string;
  /** The path and the query: what `signIn` sends the browser back to. */
  url: string;
  query: Record<string, string>;
  /** A route's `:name` segments, and `*`: the rest a final `*` matched. */
  params: Record<string, string>;
  /** Middleware may set and delete: what goes on (to a route, the app behind) carries the change. */
  headers: Headers;
  cookies: Record<string, string>;
  /** The client's address (behind proxies of yours: `app.trustProxy`). */
  ip: string;
  /** The body: routes only (middleware gets the headers; the body streams on untouched). */
  text(): Promise<string>; json<T = any>(): Promise<T>; bytes(): Promise<Uint8Array>;
}
/** A path pattern: `/jobs/:id`, `/admin/*` (`/admin` and everything under it), `*` (every path). */
export type Pattern = string;
export interface MiddlewareDefinition {
  /** The paths it runs for. sqzdb's own (`/api/…`, `/mcp`, `/oauth/…`, `/_sqz/…`) never: their own rules hold there. */
  match: Pattern | readonly Pattern[];
  /** Lower runs first (default 0); then by file and name. */
  order?: number;
  /** false: deployed, but run by the console's Try panel only; the app server skips it. */
  enabled?: boolean;
  /** Return a Response to answer the request; nothing to let it go on. */
  run(ctx: Context, req: Request): ResponseLike | void | Promise<ResponseLike | void>;
}
export interface RouteDefinition {
  path: Pattern;
  /** Default 'GET' (which answers HEAD too). */
  method?: string | readonly string[];
  /** Who may call it; without roles, anyone (check `ctx.user` yourself). */
  roles?: readonly string[];
  description?: string;
  /** false: deployed, but answered for the console's Try panel only; the app server passes the request on. */
  enabled?: boolean;
  /** A Response; or a value, sent as JSON; or nothing (204). */
  run(ctx: Context, req: Request): unknown;
}
export function middleware(def: MiddlewareDefinition): Readonly<MiddlewareDefinition>;
export function route(def: RouteDefinition): Readonly<RouteDefinition>;
/** A redirect to the API's sign-in page (or `page`), and back to `req.url` after. */
export function signIn(req: Request, page?: string): Response;
