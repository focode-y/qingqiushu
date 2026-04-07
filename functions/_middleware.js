import { getCookie, verifySignedToken } from './_lib/auth.js';
import { findSessionByRawToken } from './_lib/db.js';


const PASS_PAGES = new Set(['/invite.html', '/admin-enter.html']);

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (path.startsWith('/api/') || PASS_PAGES.has(path) || path === '/favicon.ico') {
    return next();
  }

  const signed = getCookie(request, 'access_session');
  if (!signed) {
    return Response.redirect(new URL('/invite.html', url), 302);
  }

  const raw = await verifySignedToken(signed, env.SESSION_SIGNING_KEY || '');
  if (!raw) {
    return Response.redirect(new URL('/invite.html', url), 302);
  }

  const session = await findSessionByRawToken(env, raw);
  if (!session) {
    return Response.redirect(new URL('/invite.html', url), 302);
  }

  return next();
}

