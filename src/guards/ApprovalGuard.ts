/**
 * @fileoverview ApprovalGuard - Human-in-the-Loop Gate.
 * 
 * Provides async approval gates for critical operations.
 * When a tool is flagged as critical, execution pauses until
 * an external signal approves or rejects the action.
 * 
 * @example
 * const guard = createApprovalGuard({
 *   criticalTools: ['fs:deleteFile', 'db:dropTable', 'admin:*'],
 *   approvalHandler: async (ctx) => {
 *     // Send notification and wait for approval
 *     return await slackApprovalBot.requestApproval(ctx);
 *   },
 *   timeoutMs: 300_000, // 5 minutes
 * });
 */

import type { Guard, ApprovalHandler, ToolCallContext } from '../types.js';
import { ApprovalTimeoutError } from '../types.js';
import { matchPattern } from '../utils/patterns.js';

/**
 * Configuration for the ApprovalGuard.
 */
export interface ApprovalGuardConfig {
    /**
     * List of tool name patterns that require approval.
     * Supports glob patterns like "admin:*" or "db:delete*".
     */
    readonly criticalTools: readonly string[];

    /**
     * Handler function called when approval is needed.
     * Should display the request to a human and return their decision.
     */
    readonly approvalHandler: ApprovalHandler;

    /**
     * Timeout for approval requests in milliseconds.
     * @default 300000 (5 minutes)
     */
    readonly timeoutMs?: number;

    /**
     * Action to take on timeout.
     * @default 'deny'
     */
    readonly onTimeout?: 'deny' | 'allow';

    /**
     * Optional callback when approval is requested.
     * Useful for logging or notifications.
     */
    readonly onApprovalRequested?: (ctx: ToolCallContext) => void;

    /**
     * Optional callback when approval is received.
     * Useful for audit logging.
     */
    readonly onApprovalReceived?: (ctx: ToolCallContext, approved: boolean) => void;
}

/**
 * Creates a promise that rejects after the specified timeout.
 */
function createTimeout(ms: number, toolName: string): Promise<never> {
    return new Promise((_, reject) => {
        setTimeout(() => {
            reject(new ApprovalTimeoutError(toolName, ms));
        }, ms);
    });
}

/**
 * Checks if a tool requires approval based on critical tool patterns.
 */
function requiresApproval(
    toolName: string,
    criticalTools: readonly string[]
): boolean {
    return criticalTools.some(pattern => matchPattern(pattern, toolName));
}

/**
 * Creates an ApprovalGuard for human-in-the-loop verification.
 * 
 * Critical tools trigger an async approval flow where execution
 * is paused until a human approves or rejects the action.
 * 
 * @param config - Guard configuration
 * @returns A Guard function for approval gates
 * 
 * @example
 * const guard = createApprovalGuard({
 *   criticalTools: ['fs:delete*', 'db:drop*', 'admin:*'],
 *   approvalHandler: async (ctx) => {
 *     console.log(`Approval requested for: ${ctx.toolName}`);
 *     // In production, integrate with Slack, email, or approval UI
 *     return await getHumanApproval(ctx);
 *   },
 *   timeoutMs: 60_000,
 *   onTimeout: 'deny',
 * });
 */
export function createApprovalGuard(config: ApprovalGuardConfig): Guard {
    const {
        criticalTools,
        approvalHandler,
        timeoutMs = 300_000,
        onTimeout = 'deny',
        onApprovalRequested,
        onApprovalReceived,
    } = config;

    return async (ctx) => {
        // Check if this tool requires approval
        if (!requiresApproval(ctx.toolName, criticalTools)) {
            return { allowed: true };
        }

        // Notify that approval is being requested
        onApprovalRequested?.(ctx);

        try {
            // Race between approval handler and timeout
            const approved = await Promise.race([
                approvalHandler(ctx),
                createTimeout(timeoutMs, ctx.toolName),
            ]);

            // Notify of the result
            onApprovalReceived?.(ctx, approved);

            if (approved) {
                return { allowed: true };
            }

            return {
                allowed: false,
                reason: `Approval denied for tool "${ctx.toolName}"`,
            };
        } catch (error) {
            if (error instanceof ApprovalTimeoutError) {
                // Handle timeout based on configuration
                onApprovalReceived?.(ctx, false);

                if (onTimeout === 'allow') {
                    return { allowed: true };
                }

                return {
                    allowed: false,
                    reason: `Approval timed out for tool "${ctx.toolName}" after ${timeoutMs}ms`,
                };
            }

            // Unexpected error - fail closed
            const message = error instanceof Error ? error.message : String(error);
            onApprovalReceived?.(ctx, false);

            return {
                allowed: false,
                reason: `Approval process failed: ${message}`,
            };
        }
    };
}

/**
 * Creates an approval context formatter for display to approvers.
 * 
 * @param ctx - The tool call context
 * @returns Formatted string for human review
 */
export function formatApprovalRequest(ctx: ToolCallContext): string {
    const lines = [
        '═══════════════════════════════════════════════════',
        '🔒 APPROVAL REQUIRED',
        '═══════════════════════════════════════════════════',
        '',
        `Tool: ${ctx.toolName}`,
        '',
        'Arguments:',
        JSON.stringify(ctx.args, null, 2),
    ];

    if (ctx.userPrompt) {
        lines.push('', 'Original User Request:', ctx.userPrompt);
    }

    lines.push(
        '',
        '═══════════════════════════════════════════════════',
        'Approve this action? (yes/no)',
        '═══════════════════════════════════════════════════',
    );

    return lines.join('\n');
}

/**
 * Creates a simple console-based approval handler for development.
 * NOT recommended for production use.
 * 
 * @returns An ApprovalHandler that prompts in the console
 */
export function createConsoleApprovalHandler(): ApprovalHandler {
    return async (ctx) => {
        const message = formatApprovalRequest(ctx);
        console.log(message);

        // In a real implementation, this would wait for user input
        // For now, we'll simulate auto-denial for safety
        console.log('[mcp-guard] Console approval handler - auto-denying for safety');
        return false;
    };
}
