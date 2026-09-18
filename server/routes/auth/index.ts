import passport from "@outlinewiki/koa-passport";
import { addMonths } from "date-fns";
import JWT from "jsonwebtoken";
import Koa from "koa";
import bodyParser from "koa-body";
import Router from "koa-router";
import { getWorkspaceSessionSource } from "@server/utils/workspaceAuthentication";
import { z } from "zod";
import env from "@server/env";
import { AuthenticationError, NotFoundError } from "@server/errors";
import authMiddleware from "@server/middlewares/authentication";
import coalesceBody from "@server/middlewares/coaleseBody";
import { Collection, Team, User, View } from "@server/models";
import AuthenticationHelper from "@server/models/helpers/AuthenticationHelper";
import type { AppState, AppContext, APIContext } from "@server/types";
import { AuthenticationType } from "@server/types";
import { verifyCSRFToken } from "@server/middlewares/csrf";
import { getJWTPayload } from "@server/utils/jwt";
import {
  rememberWorkspaceSession,
  selectWorkspace,
} from "@server/utils/workspaceSessions";

const app = new Koa<AppState, AppContext>();
const router = new Router();

router.use(passport.initialize());

// Reusable local testing credentials are deliberately separate from session
// tokens, so logging out does not invalidate the developer's login link.
router.get("/development", async (ctx: APIContext) => {
  const localHosts = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
  const localAddresses = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);
  if (
    !env.isDevelopment ||
    !localHosts.has(new URL(env.URL).hostname) ||
    !localHosts.has(ctx.hostname) ||
    !localAddresses.has(ctx.req.socket.remoteAddress ?? "")
  ) {
    throw NotFoundError();
  }

  ctx.set("Cache-Control", "no-store");
  ctx.set("Referrer-Policy", "no-referrer");
  const token = ctx.query.token;
  if (typeof token !== "string") {
    throw AuthenticationError();
  }

  const claims = (() => {
    try {
      return z
        .object({ type: z.literal("local-admin"), userId: z.uuid() })
        .parse(JWT.verify(token, env.UTILS_SECRET, { algorithms: ["HS256"] }));
    } catch {
      throw AuthenticationError();
    }
  })();
  const user = await User.findByPk(claims.userId, {
    include: [{ model: Team, as: "team", required: true }],
  });
  if (!user?.isAdmin || user.isSuspended) {
    throw AuthenticationError();
  }

  ctx.redirect(
    `${env.URL}/auth/redirect?token=${user.getTransferToken("email")}`
  );
});

// dynamically register available authentication provider routes
void (async () => {
  for (const provider of AuthenticationHelper.providers) {
    const resolvedRouter = await provider.value.router;
    if (resolvedRouter) {
      router.use(
        "/",
        authMiddleware({ optional: true }),
        resolvedRouter.routes()
      );
    }
  }
})();

router.get(
  "/redirect",
  authMiddleware({ type: AuthenticationType.APP }),
  async (ctx: APIContext) => {
    const { user, service } = ctx.state.auth;

    const payload = getJWTPayload(ctx.state.auth.token);
    if (payload.type !== "transfer") {
      throw AuthenticationError("Cannot extend token");
    }

    const expires = payload.workspaceSessionSource
      ? new Date(
          getJWTPayload(
            await getWorkspaceSessionSource(payload.workspaceSessionSource)
          ).expiresAt
        )
      : payload.sessionExpiresAt
        ? new Date(
            Math.min(
              new Date(payload.sessionExpiresAt).getTime(),
              addMonths(new Date(), 3).getTime()
            )
          )
        : addMonths(new Date(), 3);
    const jwtToken = user.getSessionToken(
      expires,
      service,
      payload.workspaceSessionSource
    );

    // ensure that the lastActiveAt on user is updated to prevent replay requests
    await user.updateActiveAt(ctx, true);

    rememberWorkspaceSession(ctx, user, jwtToken);
    selectWorkspace(ctx, user.teamId);

    ctx.cookies.set("accessToken", jwtToken, {
      sameSite: "lax",
      expires,
    });
    const [team, collection, view] = await Promise.all([
      Team.findByPk(user.teamId),
      Collection.findFirstCollectionForUser(user),
      View.findOne({
        where: {
          userId: user.id,
        },
      }),
    ]);

    const defaultCollectionId = team?.defaultCollectionId;

    if (defaultCollectionId) {
      const collection = await Collection.findOne({
        where: {
          id: defaultCollectionId,
          teamId: team.id,
        },
      });

      if (collection) {
        ctx.redirect(`${team.url}${collection.path}`);
        return;
      }
    }

    const hasViewedDocuments = !!view;

    ctx.redirect(
      !hasViewedDocuments && collection
        ? `${team?.url}${collection.path}/recent`
        : `${team?.url}/home`
    );
  }
);

app.use(bodyParser());
app.use(coalesceBody());
app.use(verifyCSRFToken());
app.use(router.routes());

export default app;
