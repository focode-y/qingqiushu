import { json, randomCode, setCookie, sha256Hex, signToken } from '../../_lib/auth.js';


export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const secret = String(body.secret || '');
  if (!secret || secret !== (env.ADMIN_SECRET || '')) {
    return json({ ok: false }, 403);
  }

  const rawToken = randomCode(48);
  const tokenHash = await sha256Hex(rawToken);
  const nowIso = new Date().toISOString();
  const expire = new Date(Date.now() + 60 * 24 * 3600 * 1000).toISOString();
  const ip = request.headers.get('cf-connecting-ip') || '';
  const ua = request.headers.get('user-agent') || '';

  await env.DB.prepare(
    `INSERT INTO access_sessions (id, token_hash, role, invite_id, issued_at, expires_at, last_seen_at, ip_first, ua_first, status)
     VALUES (?, ?, 'admin', null, ?, ?, ?, ?, ?, 'active')`
  ).bind(crypto.randomUUID(), tokenHash, nowIso, expire, nowIso, ip, ua).run();

  const signed = await signToken(rawToken, env.SESSION_SIGNING_KEY || '');
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=UTF-8',
      'set-cookie': setCookie('access_session', signed, 60 * 24 * 3600),
    },
  });
}

