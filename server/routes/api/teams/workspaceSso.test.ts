import { randomUUID } from "node:crypto";
import { AuthenticationProvider, UserAuthentication } from "@server/models";
import { buildAdmin, buildTeam, buildUser } from "@server/test/factories";
import { getTestServer, setSelfHosted } from "@server/test/support";
import { getJWTPayload, getUserForJWT } from "@server/utils/jwt";

const server = getTestServer();

async function setupMemberships() {
  const sourceTeam = await buildTeam({
    authenticationProviders: [{ name: "google", providerId: "example.com" }],
  });
  const targetTeam = await buildTeam({
    authenticationProviders: [{ name: "google", providerId: "example.com" }],
  });
  const source = await buildAdmin({ teamId: sourceTeam.id });
  const target = await buildUser({
    teamId: targetTeam.id,
    email: source.email,
  });
  const subject = randomUUID();
  for (const user of [source, target]) {
    await UserAuthentication.destroy({ where: { userId: user.id } });
    const provider = await AuthenticationProvider.findOne({
      where: { teamId: user.teamId, name: "google" },
      rejectOnEmpty: true,
    });
    await UserAuthentication.create({
      userId: user.id,
      authenticationProviderId: provider.id,
      providerId: subject,
      scopes: [],
    });
  }
  const expires = new Date(Date.now() + 600_000);
  const token = source.getSessionToken(expires, "google");
  const switchWorkspace = async (credential = token) => {
    const res = await server.post("/api/teams.switch", {
      headers: { Authorization: `Bearer ${credential}` },
      body: { id: target.teamId },
    });
    expect(res.status).toBe(200);
    return new URL((await res.json()).data.redirectUrl);
  };
  return { source, target, expires, token, switchWorkspace };
}

describe("Google workspace SSO", () => {
  beforeEach(() => setSelfHosted());

  it("switches after one login with no destination cookie and preserves the destination role", async () => {
    const { target, switchWorkspace } = await setupMemberships();
    const url = await switchWorkspace();
    expect(url.pathname).toBe("/auth/redirect");
    const result = await getUserForJWT(url.searchParams.get("token") ?? "");
    expect(result.user.id).toBe(target.id);
    expect(result.user.isAdmin).toBe(false);
  });

  it("bounds the destination session by the source login expiry and revocation", async () => {
    const { source, expires, switchWorkspace } = await setupMemberships();
    const url = await switchWorkspace();
    expect(url.pathname).toBe("/auth/redirect");
    const res = await server.get(url.pathname + url.search, {
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const cookies = res.headers.raw()["set-cookie"];
    const cookie = cookies.find((value) => value.startsWith("accessToken="));
    const token = cookie?.split(";")[0].slice("accessToken=".length) ?? "";
    expect(getJWTPayload(token).expiresAt).toBe(expires.toISOString());
    await expect(getUserForJWT(token)).resolves.toBeTruthy();
    await source.rotateJwtSecret({});
    await expect(getUserForJWT(token)).rejects.toThrow();
  });

  it("keeps the long-lived source credential out of the transfer URL", async () => {
    const { token, switchWorkspace } = await setupMemberships();
    const url = await switchWorkspace();
    const payload = getJWTPayload(url.searchParams.get("token") ?? "");
    expect(JSON.stringify(payload)).not.toContain(token);
  });

  it.each(["disabled-provider", "removed-membership"])(
    "invalidates a switched session after %s",
    async (condition) => {
      const { target, switchWorkspace } = await setupMemberships();
      const url = await switchWorkspace();
      const token = url.searchParams.get("token") ?? "";
      await expect(getUserForJWT(token)).resolves.toBeTruthy();
      if (condition === "disabled-provider") {
        await AuthenticationProvider.update(
          { enabled: false },
          { where: { teamId: target.teamId } }
        );
      } else {
        await UserAuthentication.destroy({ where: { userId: target.id } });
      }
      await expect(getUserForJWT(token)).rejects.toThrow();
    }
  );

  it("does not extend a saved destination session when switching back", async () => {
    const { source, target, token, expires } = await setupMemberships();
    const response = await server.post("/api/teams.switch", {
      headers: {
        Authorization: `Bearer ${target.getSessionToken(expires, "google")}`,
        Cookie: `workspaceSession-${source.teamId}=${token}`,
      },
      body: { id: source.teamId },
    });
    const url = new URL((await response.json()).data.redirectUrl);
    const res = await server.get(url.pathname + url.search, {
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const cookies = res.headers.raw()["set-cookie"];
    const cookie = cookies.find((value) => value.startsWith("accessToken="));
    const session = cookie?.split(";")[0].slice("accessToken=".length) ?? "";
    expect(getJWTPayload(session).expiresAt).toBe(expires.toISOString());
  });

  it("logout from a switched workspace invalidates the original login", async () => {
    const { token, switchWorkspace } = await setupMemberships();
    const url = await switchWorkspace();
    const res = await server.get(url.pathname + url.search, {
      redirect: "manual",
    });
    const cookies = res.headers.raw()["set-cookie"];
    const cookie = cookies.find((value) => value.startsWith("accessToken="));
    const destinationToken =
      cookie?.split(";")[0].slice("accessToken=".length) ?? "";
    const logout = await server.post("/api/auth.delete", {
      headers: { Authorization: `Bearer ${destinationToken}` },
    });
    expect(logout.status).toBe(200);
    await expect(getUserForJWT(token)).rejects.toThrow();
    await expect(getUserForJWT(destinationToken)).rejects.toThrow();
  });

  it.each([
    "different-subject",
    "disabled-source",
    "disabled-target",
    "suspended-target",
    "email-login",
  ])(
    "requires login for %s instead of trusting matching emails",
    async (condition) => {
      const { source, target, switchWorkspace } = await setupMemberships();
      if (condition === "different-subject") {
        await UserAuthentication.update(
          { providerId: randomUUID() },
          { where: { userId: target.id } }
        );
      }
      if (condition.startsWith("disabled-")) {
        await AuthenticationProvider.update(
          { enabled: false },
          {
            where: {
              teamId:
                condition === "disabled-source" ? source.teamId : target.teamId,
            },
          }
        );
      }
      if (condition === "suspended-target") {
        await target.update({ suspendedAt: new Date() });
      }
      const url = await switchWorkspace(
        condition === "email-login"
          ? source.getSessionToken(new Date(Date.now() + 600_000), "email")
          : undefined
      );
      expect(url.pathname).toBe("/");
      expect(url.searchParams.get("workspace")).toBe(target.teamId);
      expect(url.searchParams.has("token")).toBe(false);
    }
  );
});
