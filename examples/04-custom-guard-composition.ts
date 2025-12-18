/**
 * @fileoverview Custom Guard Composition Example
 * 
 * This example demonstrates advanced usage: creating custom guards
 * and composing them using functional utilities.
 * 
 * Run: npx ts-node examples/04-custom-guard-composition.ts
 */

import { Forge } from 'mcp-forge';
import { z } from 'zod';
import {
    mcpGuard,
    // Guard factories
    createStaticGuard,
    createValidationGuard,
    createApprovalGuard,
    // Composition utilities
    pipe,
    when,
    unless,
    safe,
    deny,
    // Types
    type Guard,
    type ToolCallContext,
    type GuardResult,
} from 'mcp-guard';

const forge = new Forge({
    name: 'custom-guard-server',
    version: '1.0.0',
});

// ============================================================================
// Custom Guard: Rate Limiting by Tool
// ============================================================================
function createRateLimitGuard(limits: Record<string, number>): Guard {
    const callCounts = new Map<string, { count: number; resetAt: number }>();

    return async (ctx: ToolCallContext): Promise<GuardResult> => {
        const limit = limits[ctx.toolName];
        if (!limit) return { allowed: true };

        const now = Date.now();
        const state = callCounts.get(ctx.toolName) ?? { count: 0, resetAt: now + 60000 };

        // Reset if window expired
        if (now > state.resetAt) {
            state.count = 0;
            state.resetAt = now + 60000;
        }

        state.count++;
        callCounts.set(ctx.toolName, state);

        if (state.count > limit) {
            return {
                allowed: false,
                reason: `Rate limit exceeded for ${ctx.toolName}: ${limit} calls per minute`,
            };
        }

        return { allowed: true };
    };
}

// ============================================================================
// Custom Guard: Business Hours Only
// ============================================================================
function createBusinessHoursGuard(tools: string[]): Guard {
    return async (ctx: ToolCallContext): Promise<GuardResult> => {
        if (!tools.includes(ctx.toolName)) {
            return { allowed: true };
        }

        const hour = new Date().getHours();
        const isBusinessHours = hour >= 9 && hour < 17;

        if (!isBusinessHours) {
            return {
                allowed: false,
                reason: `Tool ${ctx.toolName} is only available during business hours (9 AM - 5 PM)`,
            };
        }

        return { allowed: true };
    };
}

// ============================================================================
// Custom Guard: Audit Logging
// ============================================================================
function createAuditGuard(logFn: (entry: object) => void): Guard {
    return async (ctx: ToolCallContext): Promise<GuardResult> => {
        // Log all tool calls (doesn't block anything)
        logFn({
            timestamp: new Date().toISOString(),
            toolName: ctx.toolName,
            args: ctx.args,
            userPrompt: ctx.userPrompt,
        });

        return { allowed: true };
    };
}

// ============================================================================
// Compose Custom Guards with Built-in Guards
// ============================================================================

// Create individual guards
const namespaceGuard = createStaticGuard({
    rules: [
        { pattern: 'api:*', action: 'allow' },
        { pattern: 'internal:*', action: 'deny' },
    ],
    defaultAction: 'allow',
});

const validationGuard = createValidationGuard({
    schemas: {
        'api:createOrder': z.object({
            productId: z.string().uuid(),
            quantity: z.number().int().min(1).max(100),
        }),
    },
});

const rateLimitGuard = createRateLimitGuard({
    'api:createOrder': 10,      // 10 orders per minute
    'api:getProducts': 100,     // 100 product lookups per minute
});

const businessHoursGuard = createBusinessHoursGuard([
    'api:createOrder',          // Orders only during business hours
]);

const auditGuard = createAuditGuard((entry) => {
    console.log('[Audit]', JSON.stringify(entry, null, 2));
});

// ============================================================================
// Use Composition Utilities
// ============================================================================

// Compose all guards into a pipeline
const customPipeline = pipe(
    // Always log first (wrapped in safe() to catch errors)
    safe(auditGuard, 'Audit logging failed'),

    // Namespace check
    namespaceGuard,

    // Rate limiting
    rateLimitGuard,

    // Business hours check only for certain tools
    when(
        (ctx) => ctx.toolName.startsWith('api:'),
        businessHoursGuard
    ),

    // Validation
    validationGuard,
);

// Conditional guard: require extra approval on weekends
const weekendApprovalGuard = when(
    (ctx) => {
        const day = new Date().getDay();
        return day === 0 || day === 6; // Sunday or Saturday
    },
    createApprovalGuard({
        criticalTools: ['api:createOrder'],
        approvalHandler: async (ctx) => {
            console.log(`[Weekend Approval] Order requires weekend approval: ${ctx.args}`);
            return true; // Auto-approve for demo
        },
    })
);

// ============================================================================
// Apply to Forge (without using mcpGuard plugin, using raw middleware)
// ============================================================================

// Option 1: Use mcpGuard with built-in config
forge.plugin(mcpGuard({
    namespaceRules: [
        { pattern: 'api:*', action: 'allow' },
        { pattern: 'internal:*', action: 'deny' },
    ],
    parameterSchemas: {
        'api:createOrder': z.object({
            productId: z.string().uuid(),
            quantity: z.number().int().min(1).max(100),
        }),
    },
    verbose: true,
}));

// Option 2: Register custom middleware directly (commented out to avoid conflict)
// forge.use(async (ctx, next) => {
//   if (ctx.type !== 'tool') return next();
//   
//   const result = await customPipeline({
//     toolName: ctx.name,
//     args: ctx.args ?? {},
//     userPrompt: ctx.meta?.userPrompt as string,
//   });
//   
//   if (!result.allowed) {
//     throw new Error(`Guard denied: ${result.reason}`);
//   }
//   
//   return next();
// });

// ============================================================================
// Register tools
// ============================================================================

forge.tool(
    'api:createOrder',
    {
        schema: z.object({ productId: z.string(), quantity: z.number() }),
        description: 'Create a new order',
    },
    async (args) => {
        console.log('[Tool] Creating order:', args);
        return { orderId: 'ord_123', status: 'created' };
    }
);

forge.tool(
    'api:getProducts',
    {
        schema: z.object({ category: z.string().optional() }),
        description: 'Get available products',
    },
    async ({ category }) => {
        console.log('[Tool] Getting products, category:', category);
        return { products: [] };
    }
);

forge.tool(
    'internal:getSecrets',
    {
        schema: z.object({}),
        description: 'Get internal secrets (BLOCKED)',
    },
    async () => {
        return { secrets: [] };
    }
);

// ============================================================================
// Start
// ============================================================================
console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  mcp-guard Example: Custom Guard Composition                    ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  This example shows how to:                                      ║
║                                                                  ║
║  1. Create custom guards:                                        ║
║     - Rate limiting guard                                        ║
║     - Business hours guard                                       ║
║     - Audit logging guard                                        ║
║                                                                  ║
║  2. Use composition utilities:                                   ║
║     - pipe() - chain guards together                             ║
║     - when() - conditional guard execution                       ║
║     - unless() - inverse conditional                             ║
║     - safe() - wrap with error handling                          ║
║                                                                  ║
║  3. Combine custom guards with built-in guards                   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`);

forge.start();
