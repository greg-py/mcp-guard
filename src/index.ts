/**
 * @fileoverview mcp-forge-guard - Multi-layered security plugin for mcp-forge.
 * 
 * @packageDocumentation
 * 
 * mcp-forge-guard provides defense-in-depth protection for MCP tool calls through:
 * - Layer 1 (Static): Namespace Firewall with pattern-based access control
 * - Layer 2 (Validation): Zod-based parameter scrubbing and injection prevention
 * - Layer 3 (Semantic): LLM-powered intent-alignment verification
 * - Layer 4 (Approval): Human-in-the-loop gates for critical operations
 * 
 * @example
 * import { Forge } from 'mcp-forge';
 * import { mcpGuard } from 'mcp-forge-guard';
 * 
 * const forge = new Forge({ name: 'secure-server', version: '1.0.0' });
 * 
 * forge.plugin(mcpGuard({
 *   namespaceRules: [
 *     { pattern: 'public:*', action: 'allow' },
 *     { pattern: 'fs:read*', action: 'allow' },
 *     { pattern: 'fs:*', action: 'deny' },
 *   ],
 *   criticalTools: ['admin:*', 'db:drop*'],
 *   approvalHandler: async (ctx) => requestSlackApproval(ctx),
 * }));
 */

// Main plugin exports
export { McpGuard, mcpGuard, type ForgePlugin } from './plugin.js';

// Type exports
export {
    type ToolCallContext,
    type GuardResult,
    type Guard,
    type LLMProvider,
    type ApprovalHandler,
    type SecurityTier,
    type NamespaceAction,
    type NamespaceRule,
    type ToolSecurityConfig,
    type GuardConfig,
    GuardDeniedError,
    ApprovalTimeoutError,
} from './types.js';

// Configuration exports
export {
    validateConfig,
    safeValidateConfig,
    GuardConfigSchema,
    NamespaceRuleSchema,
    SecurityTierSchema,
    type ValidatedGuardConfig,
} from './config/index.js';

// Guard factory exports
export {
    createStaticGuard,
    createAllowList,
    createDenyList,
    type StaticGuardConfig,
} from './guards/StaticGuard.js';

export {
    createValidationGuard,
    createValidationGuardWithCustom,
    type ValidationGuardConfig,
} from './guards/ValidationGuard.js';

export {
    createSemanticGuard,
    createSelectiveSemanticGuard,
    type SemanticGuardConfig,
} from './guards/SemanticGuard.js';

export {
    createApprovalGuard,
    formatApprovalRequest,
    createConsoleApprovalHandler,
    type ApprovalGuardConfig,
} from './guards/ApprovalGuard.js';

// Utility exports for advanced usage
export {
    pipe,
    when,
    unless,
    withContext,
    allow,
    deny,
    safe,
} from './utils/compose.js';

export {
    matchPattern,
    extractNamespace,
    matchesAnyPattern,
} from './utils/patterns.js';
