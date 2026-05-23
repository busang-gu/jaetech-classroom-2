// 세션 헬퍼 — 쿠키 파싱 + JWT 검증
import { jwtVerify } from 'jose';

export const COOKIE_NAME = 'jl_session';

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = v;
  }
  return out;
}

// 요청에서 세션 페이로드 추출 — 무효하면 null
export async function getSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[COOKIE_NAME];
  if (!token) return null;

  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) throw new Error('JWT_SECRET not set');

  try {
    const secret = new TextEncoder().encode(jwtSecret);
    const { payload } = await jwtVerify(token, secret);
    return {
      userId: payload.userId,
      kakaoId: payload.kakaoId,
      nickname: payload.nickname,
      isAdmin: !!payload.isAdmin,
    };
  } catch {
    return null;
  }
}

// 인증 필수 — 무효면 401 응답 후 null 반환
export async function requireSession(req, res) {
  const session = await getSession(req);
  if (!session) {
    res.setHeader('Cache-Control', 'no-store');
    res.status(401).json({ error: 'unauthenticated' });
    return null;
  }
  return session;
}

// 관리자 필수
export async function requireAdmin(req, res) {
  const session = await requireSession(req, res);
  if (!session) return null;
  if (!session.isAdmin) {
    res.status(403).json({ error: 'forbidden' });
    return null;
  }
  return session;
}
