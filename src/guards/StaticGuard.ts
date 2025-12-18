/**
 * @fileoverview StaticGuard - Layer 1: Namespace Firewall.
 * 
 * Provides pattern-based access control for tool namespaces.
 * Uses glob-like patterns to allow or deny tool access based on
 * namespace prefixes (e.g., "fs:*", "db:write*").
 * 
 * @example
 * const guard = createStaticGuard({
 *   rules: [
 *     { pattern: 'safe:*', action: 'allow' },
 *     { pattern: 'fs:read*', action: 'allow' },
 *     { pattern: 'fs:*', action: 'deny' },
 *   ],
 *   defaultAction: 'deny',
 * });
 */

import type { Guard, NamespaceRule, NamespaceAction } from '../types.js';
import { matchPattern } from '../utils/patterns.js';

/**
 * Configuration for the StaticGuard.
 */
export interface StaticGuardConfig {
    /**
     * Ordered list of namespace rules.
     * First matching rule wins.
     */
    readonly rules: readonly NamespaceRule[];

    /**
     * Action to take when no rule matches.
     * @default 'deny'
     */
    readonly defaultAction?: NamespaceAction;
}

/**
 * Creates a StaticGuard that enforces namespace-based access control.
 * 
 * Rules are evaluated in order, and the first matching rule determines
 * the action. If no rule matches, the default action is applied.
 * 
 * This guard is designed for high performance with O(n) rule evaluation
 * where n is the number of rules.
 * 
 * @param config - Guard configuration
 * @returns A Guard function for namespace firewall
 * 
 * @example
 * const guard = createStaticGuard({
 *   rules: [
 *     { pattern: 'fs:read*', action: 'allow', description: 'Allow reads' },
 *     { pattern: 'fs:*', action: 'deny', description: 'Block all other fs' },
 *     { pattern: 'db:query', action: 'allow' },
 *   ],
 *   defaultAction: 'deny',
 * });
 * 
 * await guard({ toolName: 'fs:readFile', args: {} }); // { allowed: true }
 * await guard({ toolName: 'fs:delete', args: {} });   // { allowed: false }
 */
export function createStaticGuard(config: StaticGuardConfig): Guard {
    const { rules, defaultAction = 'deny' } = config;

    return async (ctx) => {
        // Find first matching rule
        for (const rule of rules) {
            if (matchPattern(rule.pattern, ctx.toolName)) {
                if (rule.action === 'allow') {
                    return { allowed: true };
                } else {
                    return {
                        allowed: false,
                        reason: rule.description ?? `Tool "${ctx.toolName}" blocked by rule: ${rule.pattern}`,
                    };
                }
            }
        }

        // No matching rule - apply default
        if (defaultAction === 'allow') {
            return { allowed: true };
        } else {
            return {
                allowed: false,
                reason: `Tool "${ctx.toolName}" not permitted (no matching rule)`,
            };
        }
    };
}

/**
 * Creates a simple allow-list guard.
 * Only tools matching one of the patterns are allowed.
 * 
 * @param patterns - Patterns to allow
 * @returns A Guard function
 */
export function createAllowList(patterns: readonly string[]): Guard {
    return createStaticGuard({
        rules: patterns.map(pattern => ({ pattern, action: 'allow' as const })),
        defaultAction: 'deny',
    });
}

/**
 * Creates a simple deny-list guard.
 * Tools matching any pattern are denied, all others allowed.
 * 
 * @param patterns - Patterns to deny
 * @returns A Guard function
 */
export function createDenyList(patterns: readonly string[]): Guard {
    return createStaticGuard({
        rules: patterns.map(pattern => ({ pattern, action: 'deny' as const })),
        defaultAction: 'allow',
    });
}
