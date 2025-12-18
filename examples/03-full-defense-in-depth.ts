/**
 * @fileoverview Full Defense-in-Depth Example
 * 
 * This example demonstrates all 4 layers of mcp-guard working together:
 * - Layer 1: Namespace Firewall
 * - Layer 2: Parameter Validation
 * - Layer 3: Semantic Inspection (LLM)
 * - Layer 4: Human-in-the-Loop Approval
 * 
 * Run: npx ts-node examples/03-full-defense-in-depth.ts
 */

import { Forge } from 'mcp-forge';
import { z } from 'zod';
import { mcpGuard, formatApprovalRequest, type ToolCallContext } from 'mcp-guard';

const forge = new Forge({
    name: 'enterprise-secure-server',
    version: '1.0.0',
});

// ============================================================================
// Simulated LLM provider for semantic inspection
// In production, replace with your actual LLM (OpenAI, Anthropic, etc.)
// ============================================================================
async function llmProvider(prompt: string): Promise<boolean> {
    console.log('\n[Semantic Guard] Analyzing tool call...');
    console.log('[Semantic Guard] Prompt sent to LLM:');
    console.log('─'.repeat(60));
    console.log(prompt.substring(0, 500) + '...');
    console.log('─'.repeat(60));

    // Simulate LLM analysis (in production, this calls your LLM API)
    // For demo: reject if the tool call seems misaligned with user intent
    const suspicious = prompt.includes('delete') && prompt.includes('weather');

    if (suspicious) {
        console.log('[Semantic Guard] ❌ SUSPICIOUS - Tool call does not align with intent');
        return false;
    }

    console.log('[Semantic Guard] ✓ ALIGNED - Tool call matches user intent');
    return true;
}

// ============================================================================
// Simulated approval handler for critical operations
// In production, integrate with Slack, email, or approval UI
// ============================================================================
async function approvalHandler(ctx: ToolCallContext): Promise<boolean> {
    console.log('\n' + '═'.repeat(60));
    console.log(formatApprovalRequest(ctx));
    console.log('═'.repeat(60));

    // Simulate user approval (in production, this waits for human input)
    // For demo: auto-approve after 1 second
    console.log('\n[Approval Gate] Waiting for human approval...');
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Simulate approval based on tool name
    const approved = !ctx.toolName.includes('dangerous');

    if (approved) {
        console.log('[Approval Gate] ✓ APPROVED by human operator');
    } else {
        console.log('[Approval Gate] ❌ REJECTED by human operator');
    }

    return approved;
}

// ============================================================================
// Configure mcp-guard with all 4 layers
// ============================================================================
forge.plugin(mcpGuard({
    // ─────────────────────────────────────────────────────────────────────────
    // Layer 1: Namespace Firewall
    // ─────────────────────────────────────────────────────────────────────────
    namespaceRules: [
        { pattern: 'public:*', action: 'allow' },
        { pattern: 'data:read*', action: 'allow' },
        { pattern: 'data:write*', action: 'allow' },
        { pattern: 'data:delete*', action: 'allow' }, // Allowed but requires approval
        { pattern: 'admin:*', action: 'deny' },       // Always blocked
    ],
    defaultNamespaceAction: 'deny',

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 2: Parameter Validation
    // ─────────────────────────────────────────────────────────────────────────
    parameterSchemas: {
        'data:readRecord': z.object({
            id: z.string().uuid('Invalid record ID format'),
        }),
        'data:writeRecord': z.object({
            id: z.string().uuid(),
            data: z.record(z.unknown()),
        }),
        'data:deleteRecord': z.object({
            id: z.string().uuid(),
            reason: z.string().min(10, 'Deletion reason must be at least 10 characters'),
        }),
    },

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 3: Semantic Inspection (LLM-based intent verification)
    // ─────────────────────────────────────────────────────────────────────────
    enableSemanticInspection: true,
    llmProvider: llmProvider,

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 4: Human-in-the-Loop Approval
    // ─────────────────────────────────────────────────────────────────────────
    criticalTools: [
        'data:delete*',     // All delete operations require approval
        '*:dangerous*',     // Any tool with 'dangerous' in the name
    ],
    approvalHandler: approvalHandler,
    approvalTimeoutMs: 30_000, // 30 second timeout

    // Logging
    verbose: true,
}));

// ============================================================================
// Register tools
// ============================================================================

forge.tool(
    'public:getStatus',
    { schema: z.object({}), description: 'Get server status' },
    async () => ({ status: 'healthy', uptime: '24h' })
);

forge.tool(
    'data:readRecord',
    {
        schema: z.object({ id: z.string() }),
        description: 'Read a data record by ID',
    },
    async ({ id }) => {
        console.log(`[Tool] Reading record: ${id}`);
        return { id, data: { name: 'Sample Record' } };
    }
);

forge.tool(
    'data:writeRecord',
    {
        schema: z.object({ id: z.string(), data: z.object({}) }),
        description: 'Write a data record',
    },
    async ({ id, data }) => {
        console.log(`[Tool] Writing record: ${id}`, data);
        return { success: true };
    }
);

forge.tool(
    'data:deleteRecord',
    {
        schema: z.object({ id: z.string(), reason: z.string() }),
        description: 'Delete a data record (REQUIRES APPROVAL)',
    },
    async ({ id, reason }) => {
        console.log(`[Tool] Deleting record: ${id}, reason: ${reason}`);
        return { deleted: true };
    }
);

// ============================================================================
// Start
// ============================================================================
console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  mcp-guard Example: Full Defense-in-Depth                       ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Layer 1 - Namespace Firewall:                                   ║
║    ✓ public:* → Allowed                                          ║
║    ✓ data:* → Allowed                                            ║
║    ✗ admin:* → Blocked                                           ║
║                                                                  ║
║  Layer 2 - Parameter Validation:                                 ║
║    - Record IDs must be valid UUIDs                              ║
║    - Delete reasons must be ≥ 10 characters                      ║
║                                                                  ║
║  Layer 3 - Semantic Inspection:                                  ║
║    - All tool calls verified against user intent                 ║
║    - Blocks misaligned requests (e.g., delete when asking about  ║
║      weather)                                                    ║
║                                                                  ║
║  Layer 4 - Approval Gate:                                        ║
║    - data:delete* requires human approval                        ║
║    - 30 second timeout                                           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`);

forge.start();
