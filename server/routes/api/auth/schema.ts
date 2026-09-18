import { z } from "zod";
import { BaseSchema } from "../schema";

export const AuthConfigSchema = BaseSchema.extend({
  body: z.object({ workspaceId: z.uuid().optional() }),
});

export type AuthConfigReq = z.infer<typeof AuthConfigSchema>;

export const AuthInfoSchema = BaseSchema;

export type AuthInfoReq = z.infer<typeof AuthInfoSchema>;

export const AuthDeleteSchema = BaseSchema;

export type AuthDeleteReq = z.infer<typeof AuthDeleteSchema>;
