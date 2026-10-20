/**
 * Default Platform Adapter - No-op implementation for CLI and testing.
 *
 * Every method logs the action and returns a success result.
 * This adapter is safe to use in any environment as it performs
 * no actual enforcement.
 *
 * @module agent-threat-rules/adapters/default-adapter
 */

import type {
  ActionResult,
  ExecutionContext,
  PlatformAdapter,
} from "../types.js";

function createResult(
  action: ActionResult["action"],
  ctx: ExecutionContext,
): ActionResult {
  return Object.freeze({
    action,
    success: true,
    message: `[${action}] logged (no-op) for verdict: ${ctx.verdict.outcome}`,
    timestamp: new Date().toISOString(),
  });
}

export class DefaultAdapter implements PlatformAdapter {
  readonly name = "default";

  async blockInput(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("block_input", ctx);
  }

  async blockOutput(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("block_output", ctx);
  }

  async blockTool(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("block_tool", ctx);
  }

  async quarantineSession(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("quarantine_session", ctx);
  }

  async resetContext(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("reset_context", ctx);
  }

  async alert(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("alert", ctx);
  }

  async shadow(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("shadow", ctx);
  }

  async snapshot(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("snapshot", ctx);
  }

  async escalate(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("escalate", ctx);
  }

  async reducePermissions(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("reduce_permissions", ctx);
  }

  async killAgent(ctx: ExecutionContext): Promise<ActionResult> {
    return createResult("kill_agent", ctx);
  }
}
