import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";
import { signJWT, verifyJWT } from "@/lib/jwt";
import { proxy } from "./proxy";

const FORGED = { "x-user-id": "forged-user", "x-user-nickname": "forged" };

/** Header names the proxy forwards to the route, or null when it passes the request through untouched. */
function forwarded(response: Response): string[] | null {
  const list = response.headers.get("x-middleware-override-headers");
  return list === null ? null : list.split(",");
}

for (const path of [
  "/api/auth/login",
  "/api/health",
  "/auth",
  "/_next/data/x.json",
  "/assets/a.png",
]) {
  test(`a public path ${path} strips client-supplied identity headers`, async () => {
    const response = await proxy(
      new NextRequest(`https://deskrpg.com${path}`, { headers: FORGED }),
    );

    assert.equal(response.headers.get("x-middleware-next"), "1");
    const names = forwarded(response);
    assert.ok(names, "the request headers must be rewritten, not passed through");
    assert.ok(!names.includes("x-user-id"));
    assert.ok(!names.includes("x-user-nickname"));
    assert.equal(response.headers.get("x-middleware-request-x-user-id"), null);
  });
}

test("a public path keeps the other request headers", async () => {
  const response = await proxy(
    new NextRequest("https://deskrpg.com/api/auth/login", {
      headers: { ...FORGED, "content-type": "application/json" },
    }),
  );

  assert.ok(forwarded(response)?.includes("content-type"));
  assert.equal(response.headers.get("x-middleware-request-content-type"), "application/json");
});

test("an authenticated path overwrites a forged x-user-id with the token's user", async () => {
  const token = await signJWT({ userId: "real-user", nickname: "Real" });
  const response = await proxy(
    new NextRequest("https://deskrpg.com/api/channels", {
      headers: { ...FORGED, cookie: `token=${token}` },
    }),
  );

  assert.equal(response.headers.get("x-middleware-request-x-user-id"), "real-user");
  assert.equal(response.headers.get("x-middleware-request-x-user-nickname"), "Real");
});

test("local autologin is ignored in production", async () => {
  const previous = saveLocalEnv();
  assignEnv("NODE_ENV", "production");
  process.env.DESKRPG_LOCAL_AUTOLOGIN = "1";
  process.env.DESKRPG_LOCAL_USER_ID = "local-user";
  process.env.DESKRPG_LOCAL_NICKNAME = "로컬";
  try {
    const response = await proxy(new NextRequest("http://127.0.0.1:3000/game"));
    assert.equal(response.status, 307);
    assert.equal(
      new URL(response.headers.get("location") ?? "", "http://127.0.0.1:3000").pathname,
      "/auth",
    );
    assert.equal(response.headers.get("set-cookie"), null);
  } finally {
    restoreLocalEnv(previous);
  }
});

test("local autologin opens the office as the configured user", async () => {
  const previous = saveLocalEnv();
  assignEnv("NODE_ENV", "development");
  process.env.DESKRPG_LOCAL_AUTOLOGIN = "1";
  process.env.DESKRPG_LOCAL_USER_ID = "local-user";
  process.env.DESKRPG_LOCAL_NICKNAME = "로컬";
  try {
    const screen = await proxy(new NextRequest("http://127.0.0.1:3000/auth"));
    assert.equal(screen.status, 307);
    assert.equal(
      new URL(screen.headers.get("location") ?? "", "http://127.0.0.1:3000").pathname,
      "/gateways",
    );
    const cookie = screen.headers.get("set-cookie") ?? "";
    const token = cookie.split(";")[0]?.slice("token=".length) ?? "";
    assert.equal((await verifyJWT(token))?.userId, "local-user");

    const page = await proxy(new NextRequest("http://127.0.0.1:3000/game"));
    assert.equal(page.headers.get("x-middleware-request-x-user-id"), "local-user");
    assert.match(
      page.headers.get("x-middleware-request-x-user-nickname") ?? "",
      /%EB%A1%9C%EC%BB%AC/,
    );
  } finally {
    restoreLocalEnv(previous);
  }
});

function saveLocalEnv() {
  return {
    nodeEnv: process.env.NODE_ENV,
    flag: process.env.DESKRPG_LOCAL_AUTOLOGIN,
    userId: process.env.DESKRPG_LOCAL_USER_ID,
    nickname: process.env.DESKRPG_LOCAL_NICKNAME,
  };
}

function restoreLocalEnv(previous: ReturnType<typeof saveLocalEnv>) {
  assignEnv("NODE_ENV", previous.nodeEnv);
  assignEnv("DESKRPG_LOCAL_AUTOLOGIN", previous.flag);
  assignEnv("DESKRPG_LOCAL_USER_ID", previous.userId);
  assignEnv("DESKRPG_LOCAL_NICKNAME", previous.nickname);
}

function assignEnv(name: string, value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
