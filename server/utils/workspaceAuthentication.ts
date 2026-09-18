import {
  AuthenticationProvider,
  Team,
  User,
  UserAuthentication,
} from "@server/models";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import Redis from "@server/storage/redis";
import { AuthenticationError } from "@server/errors";

/**
 * Stores the original login server-side, keeping credentials out of transfer URLs.
 *
 * @param token the verified original session.
 * @param expiresAt the original session expiry.
 * @returns an opaque identifier bounded by the login lifetime.
 */
export async function createWorkspaceSessionSource(
  token: string,
  expiresAt: Date
) {
  const ttl = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
  if (!Number.isFinite(ttl) || ttl <= 0) {
    throw AuthenticationError("Expired workspace session");
  }
  const id = randomUUID();
  await Redis.defaultClient.set(`workspace-session:${id}`, token, "EX", ttl);
  return id;
}

/**
 * Loads the login anchoring a workspace session, failing closed if it is missing.
 *
 * @param id the opaque reference in a signed token.
 * @returns the original session token.
 */
export async function getWorkspaceSessionSource(id: string) {
  if (!z.uuid().safeParse(id).success) {
    throw AuthenticationError("Invalid workspace session");
  }
  const token = await Redis.defaultClient.get(`workspace-session:${id}`);
  if (!token) {
    throw AuthenticationError("Expired workspace session");
  }
  return token;
}

/**
 * Finds an existing, active membership linked to the same Google identity.
 * Email addresses alone are never used to establish workspace access.
 *
 * @param source the authenticated source membership.
 * @param teamId the destination workspace.
 * @returns the destination membership, or undefined when linkage is ambiguous.
 */
export async function getGoogleWorkspaceUser(source: User, teamId: string) {
  const identities = await UserAuthentication.findAll({
    where: { userId: source.id },
    include: [
      {
        model: AuthenticationProvider,
        as: "authenticationProvider",
        required: true,
        where: { teamId: source.teamId, name: "google", enabled: true },
      },
    ],
  });
  if (identities.length !== 1 || !identities[0].providerId) {
    return;
  }
  const identity = identities[0];
  const matches = await UserAuthentication.findAll({
    where: { providerId: identity.providerId },
    include: [
      {
        model: AuthenticationProvider,
        as: "authenticationProvider",
        required: true,
        where: {
          teamId,
          name: "google",
          enabled: true,
          providerId: identity.authenticationProvider.providerId,
        },
      },
      {
        model: User,
        as: "user",
        required: true,
        where: { teamId },
        include: [{ model: Team, as: "team", required: true }],
      },
    ],
  });
  if (matches.length !== 1 || matches[0].user.isSuspended) {
    return;
  }
  return matches[0].user;
}
