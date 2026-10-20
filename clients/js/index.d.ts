export type Value = string | number | boolean | null;
/** A FILE column's value: `url` is a signed link (an hour by default) that an <img> or a download can use. */
export interface FileValue { id: string; name: string; type: string; size: number; url: string | null; }
export type Row = Record<string, Value | FileValue>;
/** A parameter: a value, a File or Blob (uploaded first, then its id), or a file a query returned (its id). */
export type Param = Value | FileValue | Blob;

export class SqzError extends Error {
  /** AUTH, DENIED, TYPE, SYNTAX, SCHEMA, DUPLICATE, FOREIGN_KEY, CONFLICT, NOT_FOUND, TRANSACTION, ARGUMENTS, RATE_LIMITED, CLOSED, ERROR */
  readonly code: string;
}

/** `token` is absent in cookie mode: the session is the cookie. */
export interface SignedIn { token?: string; user: Row; created: boolean; }

export interface Auth {
  readonly table: string;
  /** The signed-in user's row, or null. */
  readonly user: Row | null;
  signUp(fields: Record<string, Value>, password: string): Promise<SignedIn>;
  signIn(login: string, password: string): Promise<SignedIn>;
  /** Whether users may make an account in this table from the client, and the providers they may sign in with. */
  methods(): Promise<{ signUp: boolean; providers: string[] }>;
  /** Leave for the provider (auth.oauth.<provider> on the server); `connect` finishes the sign-in on return, in the
   *  same tab (the tab keeps the verifier the returned code needs). Resolves to the URL it went to. */
  signInWith(provider: string, opts?: { returnTo?: string }): Promise<string>;
  /** Sign in a device without a browser of its own (a CLI, a script on a server): `onCode` gets a code and the page
   *  to type it on, which the user opens in a browser where they are signed in; resolves once they allow it, with a
   *  session of this device's own. Rejects with DENIED, or EXPIRED after 10 minutes. */
  signInWithDevice(opts?: { name?: string; onCode?: (c: { code: string; url: string; expiresIn: number }) => void | Promise<void>; signal?: AbortSignal }): Promise<SignedIn>;
  signOut(): Promise<void>;
  onChange(fn: (user: Row | null) => void): () => void;
}

export interface Files {
  /** Upload a File or Blob; resolves to the file, to put in a FILE column within the hour. */
  upload(data: Blob | ArrayBuffer | Uint8Array, opts?: { name?: string; type?: string }): Promise<FileValue>;
}

export interface Live {
  readonly id: number;
  /** The newest rows (null until the first result). */
  readonly rows: Row[] | null;
  close(): void;
}

export interface Client {
  readonly url: string;
  readonly auth: Auth;
  readonly files: Files;
  /** Resolves once a sign-in coming back from a provider is finished. */
  readonly ready: Promise<void>;
  sql(sql: string, params?: Param[]): Promise<Row[] & { lastInsertId?: Value }>;
  batch(statements: Array<[string, Param[]?] | { sql: string; params?: Param[] }>): Promise<Row[][]>;
  /** Call one of the app's functions as the signed-in user; resolves to what it returned. */
  call<R = unknown>(name: string, args?: Record<string, unknown>): Promise<R>;
  live(sql: string, params: Array<Value | FileValue>, fn: (rows: Row[], info: { initial: boolean }) => void, onError?: (e: SqzError) => void): Live;
  live(sql: string, fn: (rows: Row[], info: { initial: boolean }) => void, onError?: (e: SqzError) => void): Live;
  close(): void;
}

/** `cookies`: keep the session in the API's HttpOnly cookie (a page the API serves itself: app.proxy or app.staticDir);
 *  `url` then defaults to the page's own origin. */
export function connect(url?: string, opts?: { users?: string; storage?: Storage | null; fetch?: typeof fetch; WebSocket?: typeof WebSocket; cookies?: boolean }): Client;
