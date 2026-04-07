import { json, getCookie, verifySignedToken } from '../../../_lib/auth.js';
import { findSessionByRawToken, getDB } from '../../../_lib/db.js';

async function requireAdmin(request, env) {
  const signed = getCookie(request, 'access_session');
  if (!signed) return null;
  const raw = await verifySignedToken(signed, env.SESSION_SIGNING_KEY || '');
  if (!raw) return null;
  const s = await findSessionByRawToken(env, raw);
  if (!s || s.role !== 'admin') return null;
  return s;
}

export async function onRequestPost({ request, env }) {
  const DB = getDB(env);
  if (!DB) return json({ ok: false, code: 'DB_NOT_BOUND' }, 500);

  const admin = await requireAdmin(request, env);
  if (!admin) return json({ ok: false, code: 'NO_ADMIN' }, 403);

  const body = await request.json().catch(() => ({}));
  const id = String(body.id || '').trim();
  if (!id) return json({ ok: false }, 400);

  await DB.prepare(
    `UPDATE invitation_codes SET status='disabled', updated_at=? WHERE id=?`
  ).bind(new Date().toISOString(), id).run();

  return json({ ok: true });
}
