export type Value = string | number | boolean | null;
export type Row = Record<string, Value>;

export class SqweezError extends Error {
  /** AUTH, DENIED, TYPE, SYNTAX, SCHEMA, DUPLICATE, FOREIGN_KEY, CONFLICT, NOT_FOUND, TRANSACTION, ARGUMENTS, RATE_LIMITED, CLOSED, ERROR */
  readonly code: string;
}

export interface SignedIn { token: string; user: Row; created: boolean; }

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
  signOut(): Promise<void>;
  onChange(fn: (user: Row | null) => void): () => void;
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
  /** Resolves once a sign-in coming back from a provider is finished. */
  readonly ready: Promise<void>;
  sql(sql: string, params?: Value[]): Promise<Row[] & { lastInsertId?: Value }>;
  batch(statements: Array<[string, Value[]?] | { sql: string; params?: Value[] }>): Promise<Row[][]>;
  live(sql: string, params: Value[], fn: (rows: Row[], info: { initial: boolean }) => void, onError?: (e: SqweezError) => void): Live;
  live(sql: string, fn: (rows: Row[], info: { initial: boolean }) => void, onError?: (e: SqweezError) => void): Live;
  close(): void;
}

export function connect(url: string, opts?: { users?: string; storage?: Storage | null; fetch?: typeof fetch; WebSocket?: typeof WebSocket }): Client;
