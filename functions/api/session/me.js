import { json, getCookie, verifySignedToken } from '../../_lib/auth';
import { findSessionByRawToken } from '../../_lib/db';

export async function onRequestGet({ request, env }) {
  const signed = getCookie(request, 'access_session');
  if (!signed) return json({ ok: true, role: 'guest' });

  const raw = await verifySignedToken(signed, env.SESSION_SIGNING_KEY || '');
  if (!raw) return json({ ok: true, role: 'guest' });

  const session = await findSessionByRawToken(env, raw);
  if (!session) return json({ ok: true, role: 'guest' });

  return json({ ok: true, role: session.role });
}
