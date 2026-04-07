import { json, getCookie, verifySignedToken } from '../../../_lib/auth';
import { findSessionByRawToken, createInviteCode } from '../../../_lib/db';

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
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ ok: false, code: 'NO_ADMIN' }, 403);

  const body = await request.json().catch(() => ({}));
  const count = Math.min(Math.max(Number(body.count || 1), 1), 50);
  const maxUses = Math.min(Math.max(Number(body.max_uses || 1), 1), 100);
  const expiresAt = body.expires_at ? String(body.expires_at) : null;
  const note = String(body.note || '');

  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = await createInviteCode(env, { maxUses, expiresAt, note });
    codes.push(raw);
  }

  return json({ ok: true, codes });
}
