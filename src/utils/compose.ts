/**
 * @fileoverview Functional composition utilities for guard pipelines.
 * 
 * Provides pure functional patterns for composing multiple guards
 * into a single evaluation pipeline.
 */

import type { Guard, GuardResult, ToolCallContext } from '../types.js';

/**
 * Composes multiple guards into a single guard that executes them in sequence.
 * 
 * The pipeline stops at the first denial, or continues through all guards.
 * If any guard returns sanitized arguments, subsequent guards receive them.
 * 
 * @param guards - Array of guards to compose (executed left-to-right)
 * @returns A single guard that runs all guards in sequence
 * 
 * @example
 * const pipeline = pipe(staticGuard, validationGuard, semanticGuard);
 * const result = await pipeline(ctx);
 */
export function pipe(...guards: readonly Guard[]): Guard {
    return async (ctx: ToolCallContext): Promise<GuardResult> => {
        let currentCtx = ctx;

        for (const guard of guards) {
            const result = await guard(currentCtx);

            // Stop immediately on denial
            if (!result.allowed) {
                return result;
            }

            // Update context with sanitized args if provided
            if (result.sanitizedArgs) {
                currentCtx = {
                    ...currentCtx,
                    args: result.sanitizedArgs,
                };
            }
        }

        // All guards passed
        return { allowed: true };
    };
}

/**
 * Creates a guard that only runs when a condition is met.
 * If the condition is false, the guard is skipped and the call is allowed.
 * 
 * @param condition - Predicate function to test the context
 * @param guard - Guard to run if condition is true
 * @returns A conditional guard
 * 
 * @example
 * const onlyForCritical = when(
 *   ctx => criticalTools.includes(ctx.toolName),
 *   approvalGuard
 * );
 */
export function when(
    condition: (ctx: ToolCallContext) => boolean,
    guard: Guard
): Guard {
    return async (ctx) => {
        if (!condition(ctx)) {
            return { allowed: true };
        }
        return guard(ctx);
    };
}

/**
 * Creates a guard that runs unless a condition is met.
 * Inverse of `when`.
 * 
 * @param condition - Predicate function to test the context
 * @param guard - Guard to run if condition is false
 * @returns A conditional guard
 */
export function unless(
    condition: (ctx: ToolCallContext) => boolean,
    guard: Guard
): Guard {
    return when((ctx) => !condition(ctx), guard);
}

/**
 * Creates a guard that transforms the context before passing to another guard.
 * Useful for normalization or enrichment.
 * 
 * @param transform - Function to transform the context
 * @param guard - Guard to run with the transformed context
 * @returns A transformed guard
 */
export function withContext(
    transform: (ctx: ToolCallContext) => ToolCallContext,
    guard: Guard
): Guard {
    return async (ctx) => guard(transform(ctx));
}

/**
 * Creates a guard that always allows (passthrough).
 * Useful as a default or placeholder.
 */
export const allow: Guard = async () => ({ allowed: true });

/**
 * Creates a guard that always denies with a reason.
 * Useful for blocking entire namespaces or during maintenance.
 * 
 * @param reason - The denial reason
 * @returns A denying guard
 */
export function deny(reason: string): Guard {
    return async () => ({ allowed: false, reason });
}

/**
 * Wraps a guard with error handling, converting exceptions to denials.
 * 
 * @param guard - The guard to wrap
 * @param fallbackReason - Reason to use if guard throws
 * @returns A safe guard that never throws
 */
export function safe(guard: Guard, fallbackReason = 'Guard error'): Guard {
    return async (ctx) => {
        try {
            return await guard(ctx);
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { allowed: false, reason: `${fallbackReason}: ${message}` };
        }
    };
}
