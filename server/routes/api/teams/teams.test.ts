import { faker } from "@faker-js/faker";
import { randomUUID } from "node:crypto";
import { TeamDomain, User } from "@server/models";
import {
  buildAdmin,
  buildCollection,
  buildTeam,
  buildUser,
} from "@server/test/factories";
import { getTestServer, setSelfHosted } from "@server/test/support";
import { getUserForJWT } from "@server/utils/jwt";

const server = getTestServer();

describe("teams.create", () => {
  it("creates a team", async () => {
    const team = await buildTeam();
    const user = await buildAdmin({ teamId: team.id });
    const name = faker.company.name();
    const res = await server.post("/api/teams.create", user, {
      body: {
        name,
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.team.name).toEqual(name);
  });

  it("allows self-hosted admins to create an isolated workspace", async () => {
    setSelfHosted();

    const team = await buildTeam();
    const user = await buildAdmin({ teamId: team.id });
    const res = await server.post("/api/teams.create", user, {
      body: {
        name: faker.company.name(),
      },
    });
    expect(res.status).toEqual(200);
    const { data } = await res.json();
    const createdUser = await User.findOne({ where: { teamId: data.team.id } });
    expect(data.team.id).not.toEqual(team.id);
    expect(createdUser?.email).toEqual(user.email);
    expect(createdUser?.isAdmin).toBe(true);
    expect(res.headers.get("set-cookie")).toContain(
      `workspaceSession-${team.id}=`
    );
  });

  it("denies self-hosted members even when member workspace creation is enabled", async () => {
    setSelfHosted();
    const team = await buildTeam({ memberTeamCreate: true });
    const user = await buildUser({ teamId: team.id });
    const res = await server.post("/api/teams.create", user, {
      body: { name: "Engineering" },
    });
    expect(res.status).toEqual(403);
  });

  it.each(["", "  ", "x".repeat(256)])(
    "rejects an invalid workspace name",
    async (name) => {
      const user = await buildAdmin();
      const res = await server.post("/api/teams.create", user, {
        body: { name },
      });
      expect(res.status).toEqual(400);
    }
  );
});

describe("teams.switch", () => {
  it("rejects unknown workspaces without changing the current session", async () => {
    setSelfHosted();
    const user = await buildAdmin();
    const res = await server.post("/api/teams.switch", user, {
      body: { id: randomUUID() },
    });
    expect(res.status).toBe(404);
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  it("switches using a verified session for the destination workspace", async () => {
    setSelfHosted();
    const user = await buildAdmin();
    const target = await buildUser({ email: user.email });
    const res = await server.post("/api/teams.switch", user, {
      body: { id: target.teamId },
      headers: {
        Cookie: `workspaceSession-${target.teamId}=${target.getSessionToken()}`,
      },
    });
    expect(res.status).toEqual(200);
    const { data } = await res.json();
    const token = new URL(data.redirectUrl).searchParams.get("token");
    expect(token).toBeTruthy();
    const result = await getUserForJWT(token ?? "", ["transfer"]);
    expect(result.user.id).toEqual(target.id);
    expect(res.headers.get("set-cookie")).toContain(
      `workspaceSession-${user.teamId}=`
    );
  });

  it("requires fresh login when only the email matches", async () => {
    setSelfHosted();
    const user = await buildAdmin();
    const target = await buildUser({ email: user.email });
    const res = await server.post("/api/teams.switch", user, {
      body: { id: target.teamId },
    });
    expect(res.status).toEqual(200);
    const { data } = await res.json();
    expect(data.redirectUrl).toContain(`/?workspace=${target.teamId}`);
    expect(data.redirectUrl).not.toContain("token=");
  });

  it.each([
    "forged",
    "wrong-team",
    "transfer",
    "revoked",
    "suspended",
    "expired",
    "deleted",
  ])("rejects a %s destination session", async (kind) => {
    setSelfHosted();
    const user = await buildAdmin();
    const target = await buildUser({ email: user.email });
    let token = target.getSessionToken();
    if (kind === "forged") {
      token += "forged";
    }
    if (kind === "wrong-team") {
      token = user.getSessionToken();
    }
    if (kind === "transfer") {
      token = target.getTransferToken();
    }
    if (kind === "revoked") {
      await target.rotateJwtSecret({});
    }
    if (kind === "suspended") {
      await target.team.update({ suspendedAt: new Date() });
    }
    if (kind === "expired") {
      token = target.getSessionToken(new Date(0));
    }
    if (kind === "deleted") {
      await buildAdmin({ teamId: target.teamId });
      await target.destroy();
    }
    const res = await server.post("/api/teams.switch", user, {
      body: { id: target.teamId },
      headers: { Cookie: `workspaceSession-${target.teamId}=${token}` },
    });
    expect(res.status).toEqual(200);
    const { data } = await res.json();
    expect(data.redirectUrl).toContain(`/?workspace=${target.teamId}`);
    expect(data.redirectUrl).not.toContain("token=");
  });
});

describe("#team.update", () => {
  it("should update team details", async () => {
    const admin = await buildAdmin();
    const name = faker.company.name();
    const res = await server.post("/api/team.update", admin, {
      body: {
        name,
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.name).toEqual(name);
  });

  it("should update team preferences", async () => {
    const admin = await buildAdmin();
    const res = await server.post("/api/team.update", admin, {
      body: {
        preferences: {
          publicBranding: true,
        },
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.preferences.publicBranding).toBe(true);
  });

  it("should fail upon sending unknown team preference", async () => {
    const admin = await buildAdmin();
    const res = await server.post("/api/team.update", admin, {
      body: {
        preferences: {
          invalidPreference: true,
        },
      },
    });
    expect(res.status).toEqual(400);
  });

  it("should fail upon sending a team preference value of the wrong type", async () => {
    const admin = await buildAdmin();
    const res = await server.post("/api/team.update", admin, {
      body: {
        preferences: {
          publicBranding: "yes",
        },
      },
    });
    expect(res.status).toEqual(400);
  });

  it("should add avatar", async () => {
    const team = await buildTeam();
    const admin = await buildAdmin({ teamId: team.id });
    const res = await server.post("/api/team.update", admin, {
      body: {
        avatarUrl: "https://random-url.com",
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.avatarUrl).toEqual("https://random-url.com");
  });

  it("should remove avatar", async () => {
    const team = await buildTeam({ avatarUrl: "https://random-url.com" });
    const admin = await buildAdmin({ teamId: team.id });
    const res = await server.post("/api/team.update", admin, {
      body: {
        avatarUrl: null,
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.avatarUrl).toBeNull();
  });

  it("should not invalidate request if subdomain is sent as null", async () => {
    const admin = await buildAdmin();
    const res = await server.post("/api/team.update", admin, {
      body: {
        subdomain: null,
      },
    });
    expect(res.status).not.toBe(400);
  });

  it("should add new allowed Domains, removing empty string values", async () => {
    const team = await buildTeam();
    const admin = await buildAdmin({ teamId: team.id });
    const domain1 = faker.internet.domainName();
    const domain2 = faker.internet.domainName();
    const res = await server.post("/api/team.update", admin, {
      body: {
        allowedDomains: [domain1, "", domain2, "", ""],
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.allowedDomains.includes(domain1)).toBe(true);
    expect(body.data.allowedDomains.includes(domain2)).toBe(true);

    const teamDomains: TeamDomain[] = await TeamDomain.findAll({
      where: { teamId: team.id },
    });
    expect(teamDomains.map((d) => d.name).includes(domain1)).toBe(true);
    expect(teamDomains.map((d) => d.name).includes(domain2)).toBe(true);
  });

  it("should remove old allowed Domains", async () => {
    const team = await buildTeam();
    const admin = await buildAdmin({ teamId: team.id });
    const existingTeamDomain = await TeamDomain.create({
      teamId: team.id,
      name: faker.internet.domainName(),
      createdById: admin.id,
    });

    const res = await server.post("/api/team.update", admin, {
      body: {
        allowedDomains: [],
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.allowedDomains).toEqual([]);

    const teamDomains: TeamDomain[] = await TeamDomain.findAll({
      where: { teamId: team.id },
    });
    expect(teamDomains.map((d) => d.name)).toEqual([]);

    expect(await TeamDomain.findByPk(existingTeamDomain.id)).toBeNull();
  });

  it("should add new allowed domains and remove old ones", async () => {
    const team = await buildTeam();
    const admin = await buildAdmin({ teamId: team.id });
    const existingTeamDomain = await TeamDomain.create({
      teamId: team.id,
      name: faker.internet.domainName(),
      createdById: admin.id,
    });
    const domain1 = faker.internet.domainName();
    const domain2 = faker.internet.domainName();

    const res = await server.post("/api/team.update", admin, {
      body: {
        allowedDomains: [domain1, domain2],
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.allowedDomains.includes(domain1)).toBe(true);
    expect(body.data.allowedDomains.includes(domain2)).toBe(true);

    const teamDomains: TeamDomain[] = await TeamDomain.findAll({
      where: { teamId: team.id },
    });
    expect(teamDomains.map((d) => d.name).includes(domain1)).toBe(true);
    expect(teamDomains.map((d) => d.name).includes(domain2)).toBe(true);
    expect(await TeamDomain.findByPk(existingTeamDomain.id)).toBeNull();
  });

  it("should only allow member,viewer or admin as default role", async () => {
    const admin = await buildAdmin();
    const res = await server.post("/api/team.update", admin, {
      body: {
        defaultUserRole: "New name",
      },
    });
    expect(res.status).toEqual(400);
    const successRes = await server.post("/api/team.update", admin, {
      body: {
        defaultUserRole: "viewer",
      },
    });
    const body = await successRes.json();
    expect(successRes.status).toEqual(200);
    expect(body.data.defaultUserRole).toBe("viewer");
  });

  it("should allow identical team details", async () => {
    const team = await buildTeam();
    const admin = await buildAdmin({ teamId: team.id });
    const res = await server.post("/api/team.update", admin, {
      body: {
        name: team.name,
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.name).toEqual(team.name);
  });

  it("should require admin", async () => {
    const user = await buildUser();
    const res = await server.post("/api/team.update", user, {
      body: {
        name: faker.company.name(),
      },
    });
    expect(res.status).toEqual(403);
  });

  it("should require authentication", async () => {
    const res = await server.post("/api/team.update");
    expect(res.status).toEqual(401);
  });

  it("should not allow setting team name to null", async () => {
    const admin = await buildAdmin();
    const res = await server.post("/api/team.update", admin, {
      body: {
        name: null,
      },
    });
    expect(res.status).toEqual(400);
  });

  it("should update default collection", async () => {
    const team = await buildTeam();
    const admin = await buildAdmin({ teamId: team.id });
    const collection = await buildCollection({
      teamId: team.id,
      userId: admin.id,
    });

    const res = await server.post("/api/team.update", admin, {
      body: {
        defaultCollectionId: collection.id,
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.defaultCollectionId).toEqual(collection.id);
  });

  it("should update default collection to null when collection is made private", async () => {
    const team = await buildTeam();
    const admin = await buildAdmin({ teamId: team.id });
    const collection = await buildCollection({
      teamId: team.id,
      userId: admin.id,
    });

    await buildCollection({
      teamId: team.id,
      userId: admin.id,
    });

    const res = await server.post("/api/team.update", admin, {
      body: {
        defaultCollectionId: collection.id,
      },
    });

    const body = await res.json();
    expect(res.status).toEqual(200);
    expect(body.data.defaultCollectionId).toEqual(collection.id);

    const updateRes = await server.post("/api/collections.update", admin, {
      body: {
        id: collection.id,
        permission: null,
      },
    });

    expect(updateRes.status).toEqual(200);

    const res3 = await server.post("/api/auth.info", admin);
    const body3 = await res3.json();
    expect(res3.status).toEqual(200);
    expect(body3.data.team.defaultCollectionId).toEqual(null);
  });
});
