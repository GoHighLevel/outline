import { subHours, subMinutes } from "date-fns";
import Router from "koa-router";
import { uniqBy } from "es-toolkit/compat";
import { TeamPreference } from "@shared/types";
import { parseDomain } from "@shared/utils/domains";
import env from "@server/env";
import auth from "@server/middlewares/authentication";
import { transaction } from "@server/middlewares/transaction";
import validate from "@server/middlewares/validate";
import { Event, Team } from "@server/models";
import AuthenticationHelper from "@server/models/helpers/AuthenticationHelper";
import {
  presentUser,
  presentTeam,
  presentPolicies,
  presentProviderConfig,
  presentAvailableTeam,
  presentGroup,
  presentGroupUser,
} from "@server/presenters";
import ValidateSSOAccessTask from "@server/queues/tasks/ValidateSSOAccessTask";
import type { APIContext } from "@server/types";
import { AuthenticationType } from "@server/types";
import { getSessionsInCookie } from "@server/utils/authentication";
import RateLimiter from "@server/utils/RateLimiter";
import { getJWTPayload, getUserForJWT } from "@server/utils/jwt";
import { getWorkspaceSessionSource } from "@server/utils/workspaceAuthentication";
import {
  forgetWorkspaceSession,
  getSelfHostedTeam,
  selectWorkspace,
} from "@server/utils/workspaceSessions";
import * as T from "./schema";

const router = new Router();

router.post(
  "auth.config",
  validate(T.AuthConfigSchema),
  async (ctx: APIContext<T.AuthConfigReq>) => {
    // Self-hosted workspaces share an origin; the selected workspace supplies
    // branding and authentication settings for the login page.
    if (!env.isCloudHosted) {
      const team = await getSelfHostedTeam(ctx, ctx.input.body.workspaceId);

      if (team) {
        selectWorkspace(ctx, team.id);
        ctx.body = {
          data: {
            name: team.name,
            customTheme: team.getPreference(TeamPreference.CustomTheme),
            logo: team.getPreference(TeamPreference.PublicBranding)
              ? team.avatarUrl
              : undefined,
            providers: (await AuthenticationHelper.providersForTeam(team)).map(
              presentProviderConfig
            ),
          },
        };
        return;
      }
    }

    const domain = parseDomain(ctx.request.hostname);

    if (domain.custom) {
      const team = await Team.scope("withAuthenticationProviders").findOne({
        where: {
          domain: ctx.request.hostname.toLowerCase(),
        },
      });

      if (team) {
        ctx.body = {
          data: {
            name: team.name,
            customTheme: team.getPreference(TeamPreference.CustomTheme),
            logo: team.getPreference(TeamPreference.PublicBranding)
              ? team.avatarUrl
              : undefined,
            hostname: ctx.request.hostname,
            providers: (await AuthenticationHelper.providersForTeam(team)).map(
              presentProviderConfig
            ),
          },
        };
        return;
      }
    }

    // If subdomain signin page then we return minimal team details to allow
    // for a custom screen showing only relevant signin options for that team.
    else if (env.isCloudHosted && domain.teamSubdomain) {
      const team = await Team.scope("withAuthenticationProviders").findOne({
        where: {
          subdomain: domain.teamSubdomain,
        },
      });

      if (team) {
        ctx.body = {
          data: {
            name: team.name,
            customTheme: team.getPreference(TeamPreference.CustomTheme),
            logo: team.getPreference(TeamPreference.PublicBranding)
              ? team.avatarUrl
              : undefined,
            hostname: ctx.request.hostname,
            providers: (await AuthenticationHelper.providersForTeam(team)).map(
              presentProviderConfig
            ),
          },
        };
        return;
      }
    }

    // Otherwise, we're requesting from the standard root signin page
    ctx.body = {
      data: {
        providers: (await AuthenticationHelper.providersForTeam()).map(
          presentProviderConfig
        ),
      },
    };
  }
);

/** Authentication services that don't require SSO validation. */
const NON_SSO_SERVICES = ["email", "passkeys"];

router.post("auth.info", auth(), async (ctx: APIContext<T.AuthInfoReq>) => {
  const { user, service, type } = ctx.state.auth;
  const sessions = getSessionsInCookie(ctx);
  const signedInTeamIds = env.isCloudHosted ? Object.keys(sessions) : [];

  const [team, groups, signedInTeams, availableTeams] = await Promise.all([
    Team.scope("withDomains").findByPk(user.teamId, {
      rejectOnEmpty: true,
    }),
    user.groups(),
    Team.findAll({
      where: {
        id: signedInTeamIds,
      },
    }),
    user.availableTeams(),
  ]);

  // If the user did not _just_ sign in then we need to check if they continue
  // to have access to the workspace they are signed into. This only applies
  // to SSO sessions - email and passkey logins don't have associated
  // UserAuthentication records that need validation.
  const requiresSSOValidation = !service || !NON_SSO_SERVICES.includes(service);
  const sourceId =
    !env.isCloudHosted && type === AuthenticationType.APP
      ? getJWTPayload(ctx.state.auth.token).workspaceSessionSource
      : undefined;
  const ssoUser = sourceId
    ? (
        await getUserForJWT(await getWorkspaceSessionSource(sourceId), [
          "session",
        ])
      ).user
    : user;
  if (
    requiresSSOValidation &&
    ssoUser.lastSignedInAt &&
    ssoUser.lastSignedInAt < subHours(new Date(), 1)
  ) {
    await new ValidateSSOAccessTask()
      .schedule(
        {
          userId: ssoUser.id,
        },
        {
          jobId: `validate-sso:${ssoUser.id}`,
        }
      )
      .catch(() => {
        // Ignore errors from duplicate jobId when a validation is already queued
      });
  }

  ctx.body = {
    data: {
      user: presentUser(user, {
        includeDetails: true,
      }),
      team: presentTeam(team),
      groups: await Promise.all(groups.map(presentGroup)),
      groupUsers: groups.map((group) => presentGroupUser(group.groupUsers[0])),
      // The collaboration token is only for the client and should not be issued
      // to API or OAuth consumers
      collaborationToken:
        type === AuthenticationType.APP
          ? user.getCollaborationToken()
          : undefined,
      availableTeams: uniqBy([...signedInTeams, ...availableTeams], "id").map(
        (availableTeam) =>
          presentAvailableTeam(
            availableTeam,
            signedInTeamIds.includes(availableTeam.id) ||
              availableTeam.id === user.teamId
          )
      ),
    },
    policies: presentPolicies(user, [team, user, ...groups]),
  };
});

router.post(
  "auth.delete",
  auth(),
  transaction(),
  async (ctx: APIContext<T.AuthDeleteReq>) => {
    const { auth, transaction } = ctx.state;
    const { user, token } = auth;

    if (!env.isCloudHosted && auth.type === AuthenticationType.APP) {
      const sourceId = getJWTPayload(token).workspaceSessionSource;
      if (sourceId) {
        const source = await getUserForJWT(
          await getWorkspaceSessionSource(sourceId),
          ["session"]
        );
        if (source.user.id !== user.id) {
          await source.user.rotateJwtSecret({ transaction });
          forgetWorkspaceSession(ctx, source.user.teamId);
        }
      }
    }
    await user.rotateJwtSecret({ transaction });
    if (!env.isCloudHosted) {
      forgetWorkspaceSession(ctx, user.teamId);
    }
    await Event.createFromContext(ctx, {
      name: "users.signout",
      userId: user.id,
      data: {
        name: user.name,
      },
    });

    void RateLimiter.clearCachedToken(token);

    ctx.cookies.set("accessToken", "", {
      sameSite: "lax",
      expires: subMinutes(new Date(), 1),
    });

    ctx.body = {
      success: true,
    };
  }
);

export default router;
