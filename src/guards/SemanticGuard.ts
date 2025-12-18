/**
 * @fileoverview SemanticGuard - Layer 3: Intent-Alignment Verification.
 * 
 * Provides LLM-based semantic inspection to verify that tool calls
 * align with the original user intent. This is a defense against
 * prompt injection and tool misuse attacks.
 * 
 * The guard sends the tool call context to a secondary LLM for
 * verification, comparing the intended action to the user's request.
 * 
 * @example
 * const guard = createSemanticGuard({
 *   llmProvider: async (prompt) => {
 *     const response = await openai.chat({ messages: [{ role: 'user', content: prompt }] });
 *     return response.includes('ALIGNED');
 *   },
 * });
 */

import type { Guard, LLMProvider, ToolCallContext } from '../types.js';

/**
 * Configuration for the SemanticGuard.
 */
export interface SemanticGuardConfig {
    /**
     * LLM provider function for intent verification.
     * Must return true if the action aligns with user intent.
     */
    readonly llmProvider: LLMProvider;

    /**
     * Tools to always skip semantic inspection for.
     * Useful for low-risk or high-frequency tools.
     */
    readonly skipTools?: readonly string[];

    /**
     * Custom prompt template. Use placeholders:
     * - {toolName} - The tool being called
     * - {args} - JSON stringified arguments
     * - {userPrompt} - The original user prompt
     */
    readonly promptTemplate?: string;

    /**
     * Whether to allow when no user prompt is available.
     * @default true
     */
    readonly allowWithoutPrompt?: boolean;
}

/**
 * Default prompt template for intent verification.
 * Designed to elicit a clear yes/no response from the LLM.
 */
const DEFAULT_PROMPT_TEMPLATE = `You are a security validator. Analyze if the following tool call aligns with the user's original intent.

IMPORTANT: You must respond with ONLY "ALIGNED" or "SUSPICIOUS" followed by a brief reason.

User's Original Request:
{userPrompt}

Tool Being Called: {toolName}

Arguments:
{args}

Analysis: Does this tool call with these specific arguments align with what the user originally requested? Consider:
1. Is this tool appropriate for the user's request?
2. Are the arguments reasonable and expected?
3. Could this be an attempt to perform unauthorized actions?

Response:`;

/**
 * Builds the inspection prompt from template and context.
 */
function buildPrompt(
    template: string,
    ctx: ToolCallContext
): string {
    return template
        .replace('{toolName}', ctx.toolName)
        .replace('{args}', JSON.stringify(ctx.args, null, 2))
        .replace('{userPrompt}', ctx.userPrompt ?? '(not available)');
}

/**
 * Parses the LLM response to determine alignment.
 * Looks for keywords indicating the verification result.
 */
function parseResponse(response: boolean): boolean {
    // The LLM provider already returns a boolean
    return response;
}

/**
 * Creates a SemanticGuard that uses an LLM to verify intent alignment.
 * 
 * This guard adds latency due to the LLM call, so it should be used
 * selectively for high-risk operations. Use skipTools to bypass
 * low-risk tools.
 * 
 * @param config - Guard configuration
 * @returns A Guard function for semantic inspection
 * 
 * @example
 * const guard = createSemanticGuard({
 *   llmProvider: async (prompt) => {
 *     // Your LLM call here
 *     const result = await callLLM(prompt);
 *     return result.toUpperCase().includes('ALIGNED');
 *   },
 *   skipTools: ['status:ping', 'info:version'],
 * });
 */
export function createSemanticGuard(config: SemanticGuardConfig): Guard {
    const {
        llmProvider,
        skipTools = [],
        promptTemplate = DEFAULT_PROMPT_TEMPLATE,
        allowWithoutPrompt = true,
    } = config;

    return async (ctx) => {
        // Skip if tool is in skip list
        if (skipTools.includes(ctx.toolName)) {
            return { allowed: true };
        }

        // Handle missing user prompt
        if (!ctx.userPrompt) {
            if (allowWithoutPrompt) {
                return { allowed: true };
            }
            return {
                allowed: false,
                reason: 'Semantic inspection requires user prompt context',
            };
        }

        // Build and send the inspection prompt
        const prompt = buildPrompt(promptTemplate, ctx);

        try {
            const isAligned = await llmProvider(prompt);

            if (parseResponse(isAligned)) {
                return { allowed: true };
            }

            return {
                allowed: false,
                reason: `Tool call "${ctx.toolName}" does not align with user intent`,
            };
        } catch (error) {
            // LLM call failed - fail closed for security
            const message = error instanceof Error ? error.message : String(error);
            return {
                allowed: false,
                reason: `Semantic inspection failed: ${message}`,
            };
        }
    };
}

/**
 * Creates a semantic guard that only inspects tools matching patterns.
 * 
 * @param config - Base semantic guard config
 * @param inspectPatterns - Only inspect tools matching these patterns
 * @returns A Guard function
 */
export function createSelectiveSemanticGuard(
    config: SemanticGuardConfig,
    inspectPatterns: readonly string[]
): Guard {
    const baseGuard = createSemanticGuard(config);

    return async (ctx) => {
        // Only run inspection if tool matches any pattern
        const shouldInspect = inspectPatterns.some(pattern => {
            if (pattern === '*') return true;
            if (pattern.endsWith('*')) {
                return ctx.toolName.startsWith(pattern.slice(0, -1));
            }
            return ctx.toolName === pattern;
        });

        if (!shouldInspect) {
            return { allowed: true };
        }

        return baseGuard(ctx);
    };
}
