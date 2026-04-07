import { randomCode, sha256Hex } from './auth';

export async function createInviteCode(env, { maxUses = 1, expiresAt = null, note = '' } = {}) {
  for (let i = 0; i < 5; i++) {
    const raw = `BUS-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${randomCode(4)}-${randomCode(4)}`;
    const codeHash = await sha256Hex(raw + (env.INVITE_CODE_PEPPER || ''));
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    try {
      await env.DB.prepare(
        `INSERT INTO invitation_codes (id, code_hash, code_prefix, status, max_uses, used_count, expires_at, note, created_by, created_at, updated_at)
         VALUES (?, ?, ?, 'active', ?, 0, ?, ?, 'admin', ?, ?)`
      )
        .bind(id, codeHash, raw.slice(0, 12), maxUses, expiresAt, note, now, now)
        .run();
      return raw;
    } catch (e) {
      if (!String(e).includes('UNIQUE')) throw e;
    }
  }
  throw new Error('邀请码生成失败，请重试');
}

export async function findSessionByRawToken(env, rawToken) {
  const tokenHash = await sha256Hex(rawToken);
  const rs = await env.DB.prepare(
    `SELECT id, role, status, expires_at FROM access_sessions WHERE token_hash = ? LIMIT 1`
  ).bind(tokenHash).first();
  if (!rs) return null;
  if (rs.status !== 'active') return null;
  if (new Date(rs.expires_at).getTime() <= Date.now()) return null;
  return rs;
}
