import { json, getCookie, verifySignedToken } from '../../../_lib/auth';
import { findSessionByRawToken } from '../../../_lib/db';

async function requireAdmin(request, env) {
  const signed = getCookie(request, 'access_session');
  if (!signed) return null;
  const raw = await verifySignedToken(signed, env.SESSION_SIGNING_KEY || '');
  if (!raw) return null;
  const s = await findSessionByRawToken(env, raw);
  if (!s || s.role !== 'admin') return null;
  return s;
}

export async function onRequestGet({ request, env }) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ ok: false, code: 'NO_ADMIN' }, 403);

  const rows = await env.DB.prepare(
    `SELECT id, code_prefix, status, max_uses, used_count, expires_at, note, created_at
     FROM invitation_codes
     ORDER BY created_at DESC
     LIMIT 200`
  ).all();

  return json({ ok: true, items: rows.results || [] });
}
