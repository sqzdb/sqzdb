import { fn, middleware, route, signIn } from 'sqzdb/functions'

export const guard = middleware({ match: '/dashboard/*', run: ({ user }, req) => (user ? undefined : signIn(req)) })

export const park = fn({
  description: 'Park a job to run later',
  args: { title: 'text' },
  roles: ['member'],
  run({ admin, user }, { title }) {
    if (title.trim().length < 3) throw Object.assign(new Error('a title of at least 3 characters'), { code: 'TOO_SHORT' })
    return admin.get('INSERT INTO jobs (owner, title) VALUES (?, ?) RETURNING id', [user!.id, title.trim()])
  },
})

export const health = route({ path: '/healthz', run: ({ admin }) => ({ ok: true, jobs: admin.get('SELECT count(*) AS n FROM jobs')!.n }) })
