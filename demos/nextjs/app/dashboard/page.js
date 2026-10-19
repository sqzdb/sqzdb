import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { db } from '../../lib/db';
export const dynamic = 'force-dynamic';

// as the user who is signed in: their session cookie is the database's own
async function me() { return db().session((await cookies()).get(db().sessionCookie)?.value ?? ''); }

async function park(form) {
  'use server';
  (await me()).call('park', { title: String(form.get('title') ?? '') });
  redirect('/dashboard');
}

export default async function Dashboard() {
  const h = await headers();
  const jobs = (await me()).all('SELECT id, title FROM jobs ORDER BY id');
  return <main>
    <h1>Jobs of user {h.get('x-sqz-user')} ({h.get('x-sqz-roles')})</h1>
    <ul>{jobs.map((j) => <li key={j.id}>{j.title}</li>)}</ul>
    <form action={park}><input name="title" /><button>Park</button></form>
    <a href="/_sqz/sign-out?return=/">Sign out</a>
  </main>;
}
