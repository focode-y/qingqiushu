import { json, randomCode, sha256Hex, setCookie, signToken } from '../../_lib/auth.js';


export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const code = String(body.code || '').trim().toUpperCase();
  if (!code) return json({ ok: false, code: 'INVALID' }, 400);

  const codeHash = await sha256Hex(code + (env.INVITE_CODE_PEPPER || ''));
  const invite = await env.DB.prepare(
    `SELECT * FROM invitation_codes WHERE code_hash = ? LIMIT 1`
  ).bind(codeHash).first();

  const ip = request.headers.get('cf-connecting-ip') || '';
  const ua = request.headers.get('user-agent') || '';
  const nowIso = new Date().toISOString();

  const logFail = async (reason) => {
    await env.DB.prepare(
      `INSERT INTO invite_usages (id, invite_id, used_at, ip, ua, result, reason)
       VALUES (?, ?, ?, ?, ?, 'fail', ?)`
    ).bind(crypto.randomUUID(), invite ? invite.id : null, nowIso, ip, ua, reason).run();
  };

  if (!invite) {
    await logFail('invalid');
    return json({ ok: false, code: 'INVALID' }, 403);
  }
  if (invite.status !== 'active') {
    await logFail('disabled');
    return json({ ok: false, code: 'DISABLED' }, 403);
  }
  if (invite.expires_at && new Date(invite.expires_at).getTime() <= Date.now()) {
    await logFail('expired');
    return json({ ok: false, code: 'EXPIRED' }, 403);
  }
  if (Number(invite.used_count) >= Number(invite.max_uses)) {
    await logFail('used_up');
    return json({ ok: false, code: 'USED_UP' }, 403);
  }

  const newUsed = Number(invite.used_count) + 1;
  const nextStatus = newUsed >= Number(invite.max_uses) ? 'exhausted' : 'active';
  await env.DB.prepare(
    `UPDATE invitation_codes SET used_count = ?, status = ?, updated_at = ? WHERE id = ?`
  ).bind(newUsed, nextStatus, nowIso, invite.id).run();

  const rawToken = randomCode(48);
  const tokenHash = await sha256Hex(rawToken);
  const expire = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
  await env.DB.prepare(
    `INSERT INTO access_sessions (id, token_hash, role, invite_id, issued_at, expires_at, last_seen_at, ip_first, ua_first, status)
     VALUES (?, ?, 'user', ?, ?, ?, ?, ?, ?, 'active')`
  ).bind(crypto.randomUUID(), tokenHash, invite.id, nowIso, expire, nowIso, ip, ua).run();

  await env.DB.prepare(
    `INSERT INTO invite_usages (id, invite_id, used_at, ip, ua, result, reason)
     VALUES (?, ?, ?, ?, ?, 'success', 'ok')`
  ).bind(crypto.randomUUID(), invite.id, nowIso, ip, ua).run();

  const signed = await signToken(rawToken, env.SESSION_SIGNING_KEY || '');
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=UTF-8',
      'set-cookie': setCookie('access_session', signed, 30 * 24 * 3600),
    },
  });
}

