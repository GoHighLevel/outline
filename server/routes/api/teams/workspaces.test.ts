import { randomUUID } from "node:crypto";
import { verifyOAuthState } from "@server/utils/oauthState";
import {
  buildAdmin,
  buildDocument,
  buildTeam,
  buildUser,
} from "@server/test/factories";
import { getTestServer, setSelfHosted } from "@server/test/support";
import { getUserForJWT } from "@server/utils/jwt";

const server = getTestServer();

describe("self-hosted workspace authentication", () => {
  beforeEach(() => setSelfHosted());

  it("loads the requested workspace login settings and remembers the selection", async () => {
    await buildTeam();
    const team = await buildTeam({ name: "Engineering" });
    const res = await server.post("/api/auth.config", {
      body: { workspaceId: team.id },
    });
    expect(res.status).toBe(200);
    expect((await res.json()).data.name).toBe("Engineering");
    expect(res.headers.get("set-cookie")).toContain(`workspaceId=${team.id}`);
    const next = await server.post("/api/auth.config", {
      headers: { Cookie: `workspaceId=${team.id}` },
    });
    expect((await next.json()).data.name).toBe("Engineering");
  });

  it("does not silently select another workspace for an unknown login link", async () => {
    await buildTeam();
    const res = await server.post("/api/auth.config", {
      body: { workspaceId: randomUUID() },
    });
    expect(res.status).toBe(404);
  });

  it("completes an email verification code in the selected workspace", async () => {
    const user = await buildUser();
    const target = await buildUser({ email: user.email });
    const code = await target.getEmailVerificationCode();
    const res = await server.post("/auth/email.callback", {
      body: { email: target.email, code, follow: "true" },
      headers: { Cookie: `workspaceId=${target.teamId}` },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const cookies = res.headers.raw()["set-cookie"];
    const cookie = cookies.find((value) => value.startsWith("accessToken="));
    const token = cookie?.split(";")[0].slice("accessToken=".length);
    const result = await getUserForJWT(token ?? "");
    expect(result.user.id).toBe(target.id);
    expect(res.headers.get("set-cookie")).toContain(
      `workspaceSession-${target.teamId}=`
    );
  });

  it("sends a login code only to the selected workspace membership", async () => {
    const first = await buildTeam({ authenticationProviders: [] });
    const second = await buildTeam({ authenticationProviders: [] });
    const user = await buildUser({ teamId: first.id });
    const target = await buildUser({ teamId: second.id, email: user.email });
    const res = await server.post("/auth/email", {
      body: { email: user.email, preferOTP: true },
      headers: { Cookie: `workspaceId=${second.id}` },
    });
    expect(res.status).toBe(200);
    await user.reload();
    await target.reload();
    expect(user.lastSigninEmailSentAt).toBeNull();
    expect(target.lastSigninEmailSentAt).toBeInstanceOf(Date);
  });

  it("binds the workspace selection into signed OAuth state", async () => {
    const team = await buildTeam();
    const res = await server.get("/auth/google", {
      headers: { Cookie: `workspaceId=${team.id}` },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("location") ?? "");
    const state = verifyOAuthState(location.searchParams.get("state") ?? "");
    expect(state.workspaceId).toBe(team.id);
  });

  it("revokes and removes the remembered session on logout", async () => {
    const user = await buildAdmin();
    const token = user.getSessionToken();
    const res = await server.post("/api/auth.delete", user);
    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toContain(
      `workspaceSession-${user.teamId}=;`
    );
    await expect(getUserForJWT(token)).rejects.toThrow();
  });

  it("ignores untrusted workspace IDs in the sessions metadata cookie", async () => {
    const user = await buildAdmin();
    const other = await buildTeam();
    const res = await server.post("/api/auth.info", user, {
      headers: {
        Cookie: `sessions=${encodeURIComponent(JSON.stringify({ [other.id]: {} }))}`,
      },
    });
    expect(res.status).toBe(200);
    const { data } = await res.json();
    expect(
      data.availableTeams.map((team: { id: string }) => team.id)
    ).not.toContain(other.id);
  });

  it("remembers the target session after exchanging a transfer token", async () => {
    const user = await buildAdmin();
    const res = await server.get(
      `/auth/redirect?token=${user.getTransferToken()}`,
      { redirect: "manual" }
    );
    expect(res.status).toBe(302);
    const cookies = res.headers.raw()["set-cookie"];
    const sessionCookie = cookies.find((value) =>
      value.startsWith(`workspaceSession-${user.teamId}=`)
    );
    expect(sessionCookie).toContain("httponly");
    expect(sessionCookie).toContain("path=/api/teams.switch");
    expect(cookies.join(";")).toContain(`workspaceId=${user.teamId}`);
  });

  it("keeps documents in separate workspaces", async () => {
    const user = await buildAdmin();
    const target = await buildAdmin({ email: user.email });
    const document = await buildDocument({
      teamId: target.teamId,
      userId: target.id,
    });
    const res = await server.post("/api/documents.info", user, {
      body: { id: document.id },
    });
    expect(res.status).toBe(403);
  });
});
