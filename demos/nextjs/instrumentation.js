// The database opens with the server, so the API in front of it is listening before anyone asks.
export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs' && process.env.NEXT_PHASE !== 'phase-production-build') { const { db } = await import('./lib/db.js'); db(); }
}
