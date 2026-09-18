import { addMonths } from "date-fns";
import JWT from "jsonwebtoken";
import env from "@server/env";
import { buildAdmin, buildUser, buildCollection } from "@server/test/factories";
import { getTestServer } from "@server/test/support";
import { getJWTPayload } from "@server/utils/jwt";

const server = getTestServer();

describe("auth/development", () => {
  const originalEnvironment = env.ENVIRONMENT;

  beforeEach(() => {
    env.ENVIRONMENT = "development";
    env.URL = "http://localhost:3000";
  });

  afterEach(() => {
    env.ENVIRONMENT = originalEnvironment;
  });

  it("accepts an old reusable admin credential, including after logout", async () => {
    const user = await buildAdmin();
    const token = JWT.sign(
      { type: "local-admin", userId: user.id, iat: 946684800 },
      env.UTILS_SECRET,
      { algorithm: "HS256" }
    );
    const path = `/auth/development?token=${token}`;
    for (let attempt = 0; attempt < 2; attempt++) {
      const res = await server.get(path, { redirect: "manual" });
      expect(res.status).toBe(302);
      const redirect = new URL(res.headers.get("location") ?? "");
      const session = await server.get(redirect.pathname + redirect.search, {
        redirect: "manual",
      });
      expect(session.status).toBe(302);
      const cookies = session.headers.raw()["set-cookie"];
      const cookie = cookies.find((value) => value.startsWith("accessToken="));
      const info = await server.post("/api/auth.info", {
        headers: { Cookie: cookie?.split(";")[0] ?? "" },
      });
      expect(info.status).toBe(200);
      const { data } = await info.json();
      expect(data.user.id).toBe(user.id);
      expect(data.user.role).toBe("admin");
      await user.rotateJwtSecret({});
    }
  });

  it.each(["production", "staging", "test"])(
    "is unavailable in %s",
    async (environment) => {
      env.ENVIRONMENT = environment;
      const res = await server.get("/auth/development?token=invalid", {
        redirect: "manual",
      });
      expect(res.status).toBe(404);
    }
  );

  it("is unavailable on a public hostname", async () => {
    const res = await server.get("/auth/development?token=invalid", {
      headers: { host: "docs.example.com" },
      redirect: "manual",
    });
    expect(res.status).toBe(404);
  });

  it.each(["tampered", "wrong-type", "member", "suspended"])(
    "rejects a %s credential",
    async (kind) => {
      const user = kind === "member" ? await buildUser() : await buildAdmin();
      if (kind === "suspended") {
        await user.team.update({ suspendedAt: new Date() });
      }
      let token = JWT.sign(
        {
          type: kind === "wrong-type" ? "session" : "local-admin",
          userId: user.id,
        },
        env.UTILS_SECRET
      );
      if (kind === "tampered") {
        token += "tampered";
      }
      const res = await server.get(`/auth/development?token=${token}`, {
        redirect: "manual",
      });
      expect(res.status).toBe(401);
    }
  );
});

describe("auth/redirect", () => {
  it("should redirect to home", async () => {
    const user = await buildUser();
    const res = await server.get(
      `/auth/redirect?token=${user.getTransferToken()}`,
      {
        redirect: "manual",
      }
    );
    expect(res.status).toEqual(302);
    expect(res.headers.get("location")).not.toBeNull();
    expect(res.headers.get("location")!.endsWith("/home")).toBeTruthy();
  });

  it("should redirect to first collection", async () => {
    const collection = await buildCollection();
    const user = await buildUser({
      teamId: collection.teamId,
    });
    const res = await server.get(
      `/auth/redirect?token=${user.getTransferToken()}`,
      {
        redirect: "manual",
      }
    );
    expect(res.status).toEqual(302);
    expect(res.headers.get("location")).not.toBeNull();
    expect(res.headers.get("location")!.includes(collection.path)).toBeTruthy();
  });

  it("should issue a session token with an expiry", async () => {
    const user = await buildUser();
    const before = Date.now();
    const res = await server.get(
      `/auth/redirect?token=${user.getTransferToken()}`,
      {
        redirect: "manual",
      }
    );
    expect(res.status).toEqual(302);

    const cookie = res.headers.get("set-cookie");
    expect(cookie).not.toBeNull();
    const match = cookie!.match(/accessToken=([^;]+)/);
    expect(match).not.toBeNull();

    const payload = getJWTPayload(match![1]);
    expect(payload.type).toEqual("session");
    expect(payload.expiresAt).toBeDefined();

    const expiresAt = new Date(payload.expiresAt as string).getTime();
    const expectedMin = addMonths(before, 3).getTime() - 1000;
    const expectedMax = addMonths(Date.now(), 3).getTime() + 1000;
    expect(expiresAt).toBeGreaterThanOrEqual(expectedMin);
    expect(expiresAt).toBeLessThanOrEqual(expectedMax);
  });

  it("should prevent token extension by rejecting JWT tokens", async () => {
    const user = await buildUser();
    const jwtToken = user.getSessionToken();

    const res = await server.get(`/auth/redirect?token=${jwtToken}`, {
      redirect: "manual",
    });

    expect(res.status).toEqual(401);
  });
});
