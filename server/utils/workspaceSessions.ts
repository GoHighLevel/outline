import { addMonths } from "date-fns";
import type { Context } from "koa";
import { z } from "zod";
import env from "@server/env";
import { NotFoundError } from "@server/errors";
import { Team } from "@server/models";
import type { User } from "@server/models";

/**
 * Saves a self-hosted workspace session for explicit switching. The credential
 * is only sent to the switch endpoint and is never exposed to JavaScript.
 *
 * @param ctx the request context.
 * @param user the authenticated user.
 * @param token the existing session token, without extending its lifetime.
 */
export function rememberWorkspaceSession(
  ctx: Context,
  user: User,
  token: string
) {
  if (env.isCloudHosted) {
    return;
  }
  ctx.cookies.set(`workspaceSession-${user.teamId}`, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: ctx.secure,
    path: "/api/teams.switch",
    expires: addMonths(new Date(), 3),
  });
}

/**
 * Removes a remembered workspace credential on sign-out.
 *
 * @param ctx the request context.
 * @param teamId the workspace being signed out.
 */
export function forgetWorkspaceSession(ctx: Context, teamId: string) {
  ctx.cookies.set(`workspaceSession-${teamId}`, null, {
    path: "/api/teams.switch",
    httpOnly: true,
    sameSite: "lax",
    secure: ctx.secure,
  });
}

/**
 * Remembers the workspace whose login page should be shown. This is a routing
 * hint, never proof of membership or authentication.
 *
 * @param ctx the request context.
 * @param teamId the selected workspace.
 */
export function selectWorkspace(ctx: Context, teamId: string) {
  if (!env.isCloudHosted) {
    ctx.cookies.set("workspaceId", teamId, {
      httpOnly: true,
      sameSite: "lax",
      secure: ctx.secure,
      expires: addMonths(new Date(), 3),
    });
  }
}

/**
 * Resolves a self-hosted login selection, defaulting to the original workspace.
 * An explicit unknown workspace must never fall through to another tenant.
 *
 * @param ctx the request context.
 * @param workspaceId an explicit workspace ID from validated input or OAuth state.
 * @returns the selected workspace including its authentication providers.
 */
export async function getSelfHostedTeam(ctx: Context, workspaceId?: string) {
  const id = workspaceId ?? ctx.cookies.get("workspaceId");
  const teams = Team.scope("withAuthenticationProviders");
  if (id) {
    if (!z.uuid().safeParse(id).success) {
      throw NotFoundError("Workspace not found");
    }
    const team = await teams.findByPk(id);
    if (!team) {
      throw NotFoundError("Workspace not found");
    }
    return team;
  }
  return teams.findOne({
    order: [
      ["createdAt", "ASC"],
      ["id", "ASC"],
    ],
  });
}
