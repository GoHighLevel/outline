import Router from "koa-router";
import { UserRole } from "@shared/types";
import teamCreator from "@server/commands/teamCreator";
import teamUpdater from "@server/commands/teamUpdater";
import ConfirmTeamDeleteEmail from "@server/emails/templates/ConfirmTeamDeleteEmail";
import env from "@server/env";
import { ValidationError } from "@server/errors";
import auth from "@server/middlewares/authentication";
import { rateLimiter } from "@server/middlewares/rateLimiter";
import { transaction } from "@server/middlewares/transaction";
import validate from "@server/middlewares/validate";
import { Team, TeamDomain, User } from "@server/models";
import { authorize } from "@server/policies";
import { presentTeam, presentPolicies } from "@server/presenters";
import type { APIContext } from "@server/types";
import { AuthenticationType } from "@server/types";
import { RateLimiterStrategy } from "@server/utils/RateLimiter";
import { safeEqual } from "@server/utils/crypto";
import { getJWTPayload, getUserForJWT } from "@server/utils/jwt";
import {
  createWorkspaceSessionSource,
  getGoogleWorkspaceUser,
  getWorkspaceSessionSource,
} from "@server/utils/workspaceAuthentication";
import {
  forgetWorkspaceSession,
  rememberWorkspaceSession,
  selectWorkspace,
} from "@server/utils/workspaceSessions";
import * as T from "./schema";

const router = new Router();

const handleTeamUpdate = async (ctx: APIContext<T.TeamsUpdateSchemaReq>) => {
  const { transaction } = ctx.state;
  const { user } = ctx.state.auth;
  const team = await Team.findByPk(user.teamId, {
    include: [{ model: TeamDomain, separate: true }],
    lock: transaction.LOCK.UPDATE,
    transaction,
  });
  authorize(user, "update", team);

  const updatedTeam = await teamUpdater(ctx, {
    params: ctx.input.body,
    user,
    team,
  });

  ctx.body = {
    data: presentTeam(updatedTeam),
    policies: presentPolicies(user, [updatedTeam]),
  };
};

router.post(
  "team.update",
  rateLimiter(RateLimiterStrategy.TwentyFivePerMinute),
  auth(),
  validate(T.TeamsUpdateSchema),
  transaction(),
  handleTeamUpdate
);

router.post(
  "teams.update",
  rateLimiter(RateLimiterStrategy.TwentyFivePerMinute),
  auth(),
  validate(T.TeamsUpdateSchema),
  transaction(),
  handleTeamUpdate
);

router.post(
  "teams.requestDelete",
  rateLimiter(RateLimiterStrategy.FivePerHour),
  auth(),
  async (ctx: APIContext) => {
    if (!env.EMAIL_ENABLED) {
      throw ValidationError("Email support is not setup for this instance");
    }

    const { user } = ctx.state.auth;
    const { team } = user;
    authorize(user, "delete", team);

    await new ConfirmTeamDeleteEmail({
      to: user.email,
      language: user.language,
      deleteConfirmationCode: team.getDeleteConfirmationCode(user),
    }).schedule();

    ctx.body = {
      success: true,
    };
  }
);

router.post(
  "teams.delete",
  rateLimiter(RateLimiterStrategy.TenPerHour),
  auth(),
  validate(T.TeamsDeleteSchema),
  transaction(),
  async (ctx: APIContext<T.TeamsDeleteSchemaReq>) => {
    const { auth } = ctx.state;
    const { code } = ctx.input.body;
    const { user } = auth;
    const { team } = user;

    authorize(user, "delete", team);

    if (env.EMAIL_ENABLED) {
      const deleteConfirmationCode = team.getDeleteConfirmationCode(user);

      if (!safeEqual(code, deleteConfirmationCode)) {
        throw ValidationError("The confirmation code was incorrect");
      }
    }

    await team.destroyWithCtx(ctx);

    ctx.body = {
      success: true,
    };
  }
);

router.post(
  "teams.create",
  rateLimiter(RateLimiterStrategy.FivePerHour),
  auth({ type: AuthenticationType.APP }),
  validate(T.TeamsCreateSchema),
  transaction(),
  async (ctx: APIContext<T.TeamsCreateSchemaReq>) => {
    const { transaction } = ctx.state;
    const { user } = ctx.state.auth;
    const { name } = ctx.input.body;

    const existingTeam = await Team.scope(
      "withAuthenticationProviders"
    ).findByPk(user.teamId, {
      rejectOnEmpty: true,
      transaction,
    });

    authorize(user, "createTeam", existingTeam);

    const authenticationProviders = existingTeam.authenticationProviders.map(
      (provider) => ({
        name: provider.name,
        providerId: provider.providerId,
      })
    );

    const team = await teamCreator(ctx, {
      name,
      subdomain: name,
      authenticationProviders,
    });

    const newUser = await User.createWithCtx(ctx, {
      teamId: team.id,
      name: user.name,
      email: user.email,
      role: UserRole.Admin,
    });

    rememberWorkspaceSession(ctx, user, ctx.state.auth.token);

    ctx.body = {
      success: true,
      data: {
        team: presentTeam(team),
        transferUrl: `${
          team.url
        }/auth/redirect?token=${newUser?.getTransferToken()}`,
      },
    };
  }
);

router.post(
  "teams.switch",
  rateLimiter(RateLimiterStrategy.TwentyFivePerMinute),
  auth({ type: AuthenticationType.APP }),
  validate(T.TeamsSwitchSchema),
  async (ctx: APIContext<T.TeamsSwitchSchemaReq>) => {
    if (env.isCloudHosted) {
      throw ValidationError("Use the workspace URL to switch workspaces");
    }
    const { id } = ctx.input.body;
    const { user, token } = ctx.state.auth;
    await Team.findByPk(id, { rejectOnEmpty: true });
    rememberWorkspaceSession(ctx, user, token);
    let redirectUrl = `${env.URL}/?workspace=${id}`;
    let hasSession = false;
    const targetToken =
      id === user.teamId ? token : ctx.cookies.get(`workspaceSession-${id}`);

    if (targetToken) {
      try {
        const target = await getUserForJWT(targetToken, ["session"]);
        if (target.user.teamId === id && !target.user.isSuspended) {
          hasSession = true;
          const payload = getJWTPayload(targetToken);
          redirectUrl = `${env.URL}/auth/redirect?token=${encodeURIComponent(target.user.getTransferToken(target.service, payload.workspaceSessionSource, payload.expiresAt))}`;
        }
      } catch {
        // Revoked, expired, or otherwise invalid sessions require a fresh login.
      }
    }

    if (!hasSession && ctx.state.auth.service === "google") {
      const sourceId = getJWTPayload(token).workspaceSessionSource;
      const sourceToken = sourceId
        ? await getWorkspaceSessionSource(sourceId)
        : token;
      const source = await getUserForJWT(sourceToken, ["session"]);
      const sourcePayload = getJWTPayload(sourceToken);
      if (
        source.service === "google" &&
        Number.isFinite(new Date(sourcePayload.expiresAt).getTime())
      ) {
        const target = await getGoogleWorkspaceUser(source.user, id);
        if (target) {
          hasSession = true;
          const sessionSourceId =
            sourceId ??
            (await createWorkspaceSessionSource(
              sourceToken,
              new Date(sourcePayload.expiresAt)
            ));
          redirectUrl = `${env.URL}/auth/redirect?token=${encodeURIComponent(target.getTransferToken("google", sessionSourceId))}`;
        }
      }
    }

    if (!hasSession) {
      forgetWorkspaceSession(ctx, id);
    }
    selectWorkspace(ctx, id);
    ctx.cookies.set("accessToken", null, { sameSite: "lax" });
    ctx.body = { data: { redirectUrl } };
  }
);

export default router;
