import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";

import { setupThrowawaySqlite } from "@/test-setup/npc-seed";

setupThrowawaySqlite("gateway-url-validation");

test("testing a non-URL gateway address is a 400", async () => {
  const { POST } = await import("./test-gateway/route");
  const res = await POST(
    new NextRequest("http://localhost/api/channels/test-gateway", {
      method: "POST",
      headers: { "content-type": "application/json", "x-user-id": "user" },
      body: JSON.stringify({ url: "admin" }),
    }),
  );
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.ok, false);
  assert.equal(body.errorCode, "invalid_gateway_url");
});

test("creating a gateway with a non-URL address is a 400", async () => {
  const { POST } = await import("../gateways/route");
  const res = await POST(
    new NextRequest("http://localhost/api/gateways", {
      method: "POST",
      headers: { "content-type": "application/json", "x-user-id": "user" },
      body: JSON.stringify({ url: "admin" }),
    }),
  );
  assert.equal(res.status, 400);
  assert.equal((await res.json()).errorCode, "invalid_gateway_url");
});
