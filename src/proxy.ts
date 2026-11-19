import { NextRequest, NextResponse } from "next/server";
import { isSecureCookie, signJWT, verifyJWT, type JWTPayload } from "@/lib/jwt";

const PUBLIC_PATHS = ["/", "/auth", "/api/auth", "/api/health", "/robots.txt", "/sitemap.xml"];

/** Set only by this proxy from a verified token — never trusted from the client. */
const IDENTITY_HEADERS = ["x-user-id", "x-user-nickname"];

function isPublic(pathname: string): boolean {
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + "/"));
}

function withoutIdentityHeaders(req: NextRequest): Headers {
  const headers = new Headers(req.headers);
  for (const name of IDENTITY_HEADERS) headers.delete(name);
  return headers;
}

function isPassThrough(pathname: string): boolean {
  return isPublic(pathname) || pathname.startsWith("/_next") || pathname.startsWith("/assets");
}

function isLoginScreen(pathname: string): boolean {
  return pathname === "/" || pathname === "/auth" || pathname.startsWith("/auth/");
}

/** This machine only. Production ignores the flag so a copied env file cannot skip login. */
function localPrincipal(): JWTPayload | null {
  if (process.env.NODE_ENV === "production") return null;
  if (process.env.DESKRPG_LOCAL_AUTOLOGIN !== "1") return null;
  const userId = process.env.DESKRPG_LOCAL_USER_ID?.trim() ?? "";
  const nickname = process.env.DESKRPG_LOCAL_NICKNAME?.trim() ?? "";
  if (!userId || !nickname) return null;
  return { userId, nickname };
}

function applySession(response: NextResponse, token: string): NextResponse {
  response.cookies.set("token", token, {
    httpOnly: true,
    secure: isSecureCookie(),
    sameSite: "lax",
    maxAge: 60 * 60 * 24 * 7,
    path: "/",
  });
  return response;
}

function identify(headers: Headers, principal: JWTPayload, token?: string) {
  if (token) {
    const current = headers.get("cookie");
    const pair = `token=${token}`;
    headers.set("cookie", current ? `${current}; ${pair}` : pair);
  }
  headers.set("x-user-id", principal.userId);
  headers.set("x-user-nickname", encodeURIComponent(principal.nickname));
}

export async function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const requestHeaders = withoutIdentityHeaders(req);
  const local = localPrincipal();

  if (isPassThrough(pathname) && !local) {
    return NextResponse.next({ request: { headers: requestHeaders } });
  }

  const token = req.cookies.get("token")?.value;
  const payload = token ? await verifyJWT(token) : null;

  if (!payload && local) {
    const issued = await signJWT(local);
    if (isLoginScreen(pathname)) {
      return applySession(NextResponse.redirect(new URL("/gateways", req.url)), issued);
    }
    if (isPassThrough(pathname)) {
      return applySession(NextResponse.next({ request: { headers: requestHeaders } }), issued);
    }
    identify(requestHeaders, local, issued);
    return applySession(NextResponse.next({ request: { headers: requestHeaders } }), issued);
  }

  if (isPassThrough(pathname)) {
    return NextResponse.next({ request: { headers: requestHeaders } });
  }

  if (!payload) {
    const response = NextResponse.redirect(new URL("/auth", req.url));
    if (token) response.cookies.delete("token");
    return response;
  }

  identify(requestHeaders, payload);
  return NextResponse.next({ request: { headers: requestHeaders } });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
