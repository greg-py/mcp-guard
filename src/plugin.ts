/**
 * @fileoverview McpGuard Plugin - Main entry point for mcp-forge integration.
 * 
 * This module provides the GuardPlugin class that can be mounted onto
 * an mcp-forge application to provide multi-layered security protection
 * for tool calls.
 * 
 * @example
 * import { Forge } from 'mcp-forge';
 * import { mcpGuard } from 'mcp-forge-guard';
 * 
 * const forge = new Forge({ name: 'my-server', version: '1.0.0' });
 * 
 * forge.plugin(mcpGuard({
 *   namespaceRules: [
 *     { pattern: 'safe:*', action: 'allow' },
 *     { pattern: 'fs:read*', action: 'allow' },
 *   ],
 *   criticalTools: ['fs:delete*', 'db:drop*'],
 *   enableSemanticInspection: true,
 *   llmProvider: async (prompt) => callYourLLM(prompt),
 *   approvalHandler: async (ctx) => requestSlackApproval(ctx),
 * }));
 */

import type { GuardConfig, Guard, ToolCallContext } from './types.js';
import { GuardDeniedError } from './types.js';
import { validateConfig } from './config/schemas.js';
import { createStaticGuard } from './guards/StaticGuard.js';
import { createValidationGuard } from './guards/ValidationGuard.js';
import { createSemanticGuard } from './guards/SemanticGuard.js';
import { createApprovalGuard } from './guards/ApprovalGuard.js';
import { pipe } from './utils/compose.js';

/**
 * Type definition for mcp-forge's ForgePlugin.
 * The plugin receives the Forge instance and can register middleware/tools.
 */
export type ForgePlugin = (forge: ForgeInstance) => void;

/**
 * Minimal type definition for the Forge instance we interact with.
 * We only need the `use` method for registering middleware.
 */
interface ForgeInstance {
    use(middleware: MiddlewareFunction): ForgeInstance;
}

/**
 * Middleware context provided by mcp-forge.
 * Contains information about the current operation.
 */
interface MiddlewareContext {
    /** Type of operation: 'tool', 'resource', 'prompt' */
    type: string;
    /** Name of the tool/resource/prompt */
    name: string;
    /** Arguments passed to the operation */
    args?: Record<string, unknown>;
    /** Additional metadata */
    meta?: Record<string, unknown>;
}

/**
 * Middleware function signature for mcp-forge.
 */
type MiddlewareFunction = (
    ctx: MiddlewareContext,
    next: () => Promise<unknown>
) => Promise<unknown>;

/**
 * Builds the guard pipeline from configuration.
 * Guards are composed in order: Static → Validation → Semantic → Approval
 */
function buildGuardPipeline(config: ReturnType<typeof validateConfig>): Guard {
    const guards: Guard[] = [];

    // Layer 1: Static Guard (Namespace Firewall)
    if (config.namespaceRules && config.namespaceRules.length > 0) {
        guards.push(createStaticGuard({
            rules: config.namespaceRules,
            defaultAction: config.defaultNamespaceAction,
        }));
    }

    // Layer 2: Validation Guard (Parameter Scrubbing)
    if (config.parameterSchemas && Object.keys(config.parameterSchemas).length > 0) {
        guards.push(createValidationGuard({
            schemas: config.parameterSchemas,
            strictMode: false,
            stripUnknown: true,
        }));
    }

    // Layer 3: Semantic Guard (Intent Verification)
    if (config.enableSemanticInspection && config.llmProvider) {
        guards.push(createSemanticGuard({
            llmProvider: config.llmProvider,
        }));
    }

    // Layer 4: Approval Guard (Human-in-the-Loop)
    if (config.criticalTools && config.criticalTools.length > 0 && config.approvalHandler) {
        guards.push(createApprovalGuard({
            criticalTools: config.criticalTools,
            approvalHandler: config.approvalHandler,
            timeoutMs: config.approvalTimeoutMs,
        }));
    }

    // Return composed pipeline (or passthrough if empty)
    if (guards.length === 0) {
        return async () => ({ allowed: true });
    }

    return pipe(...guards);
}

/**
 * McpGuard class that integrates with mcp-forge's plugin system.
 * 
 * Provides multi-layered security through middleware that intercepts
 * tool calls before they execute.
 */
export class McpGuard {
    private readonly config: ReturnType<typeof validateConfig>;
    private readonly guardPipeline: Guard;

    /**
     * Creates a new McpGuard instance.
     * 
     * @param config - Guard configuration
     */
    constructor(config: GuardConfig) {
        // Validate and normalize configuration with defaults
        this.config = validateConfig(config);

        // Build the guard pipeline
        this.guardPipeline = buildGuardPipeline(this.config);
    }

    /**
     * Returns the ForgePlugin function that can be passed to forge.plugin().
     * 
     * @example
     * forge.plugin(new McpGuard(config).install);
     */
    get install(): ForgePlugin {
        return (forge: ForgeInstance) => {
            forge.use(this.createMiddleware());
        };
    }

    /**
     * Creates the middleware function for mcp-forge.
     * This is the core integration point with the framework.
     */
    private createMiddleware(): MiddlewareFunction {
        const pipeline = this.guardPipeline;
        const verbose = this.config.verbose;

        return async (ctx, next) => {
            // Only guard tool calls
            if (ctx.type !== 'tool') {
                return next();
            }

            // Build tool context for guards
            const toolCtx: ToolCallContext = {
                toolName: ctx.name,
                args: ctx.args ?? {},
                userPrompt: ctx.meta?.['userPrompt'] as string | undefined,
                meta: ctx.meta,
            };

            if (verbose) {
                console.log(`[mcp-forge-guard] Evaluating tool call: ${ctx.name}`);
            }

            // Run through guard pipeline
            const result = await pipeline(toolCtx);

            if (!result.allowed) {
                if (verbose) {
                    console.log(`[mcp-forge-guard] Denied: ${result.reason}`);
                }
                throw new GuardDeniedError('GuardPipeline', ctx.name, result.reason ?? 'Access denied');
            }

            // If guards modified the args, update the context
            // Note: This mutates the context which is expected middleware behavior
            if (result.sanitizedArgs && ctx.args) {
                Object.assign(ctx.args, result.sanitizedArgs);
            }

            if (verbose) {
                console.log(`[mcp-forge-guard] Allowed: ${ctx.name}`);
            }

            // Proceed to the actual tool execution
            return next();
        };
    }
}

/**
 * Factory function to create a McpGuard plugin.
 * This is the recommended way to integrate mcp-forge-guard with mcp-forge.
 * 
 * @param config - Guard configuration
 * @returns ForgePlugin function to pass to forge.plugin()
 * 
 * @example
 * import { Forge } from 'mcp-forge';
 * import { mcpGuard } from 'mcp-forge-guard';
 * 
 * const forge = new Forge({ name: 'my-server', version: '1.0.0' });
 * 
 * // Simple usage with namespace rules
 * forge.plugin(mcpGuard({
 *   namespaceRules: [
 *     { pattern: 'public:*', action: 'allow' },
 *     { pattern: '*', action: 'deny' },
 *   ],
 * }));
 * 
 * // Full configuration with all layers
 * forge.plugin(mcpGuard({
 *   namespaceRules: [
 *     { pattern: 'fs:read*', action: 'allow' },
 *     { pattern: 'fs:*', action: 'deny' },
 *   ],
 *   parameterSchemas: {
 *     'fs:readFile': z.object({ path: z.string() }),
 *   },
 *   criticalTools: ['admin:*'],
 *   enableSemanticInspection: true,
 *   llmProvider: async (prompt) => {
 *     // Call your LLM and return true if aligned
 *     const response = await callLLM(prompt);
 *     return response.includes('ALIGNED');
 *   },
 *   approvalHandler: async (ctx) => {
 *     // Request human approval
 *     return await requestApproval(ctx);
 *   },
 * }));
 */
export function mcpGuard(config: GuardConfig): ForgePlugin {
    const guard = new McpGuard(config);
    return guard.install;
}
