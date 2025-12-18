/**
 * @fileoverview Parameter Validation Example
 * 
 * This example demonstrates Layer 2: Zod-based parameter validation
 * with automatic injection detection and argument sanitization.
 * 
 * Run: npx ts-node examples/02-parameter-validation.ts
 */

import { Forge } from 'mcp-forge';
import { z } from 'zod';
import { mcpGuard } from 'mcp-forge-guard';

const forge = new Forge({
    name: 'validated-api-server',
    version: '1.0.0',
});

// ============================================================================
// Add mcp-forge-guard with parameter validation schemas
// ============================================================================
forge.plugin(mcpGuard({
    // Allow all tools by default (focus on validation, not namespace)
    namespaceRules: [{ pattern: '*', action: 'allow' }],

    // Define validation schemas for each tool
    parameterSchemas: {
        // User creation with strict validation
        'user:create': z.object({
            name: z.string()
                .min(1, 'Name is required')
                .max(100, 'Name too long')
                .regex(/^[a-zA-Z\s]+$/, 'Name can only contain letters'),
            email: z.string()
                .email('Invalid email format'),
            age: z.number()
                .int('Age must be an integer')
                .min(13, 'Must be at least 13 years old')
                .max(120, 'Invalid age'),
        }),

        // Database query with SQL injection protection
        'db:query': z.object({
            table: z.enum(['users', 'products', 'orders'], {
                errorMap: () => ({ message: 'Invalid table name' }),
            }),
            limit: z.number()
                .int()
                .min(1)
                .max(100)
                .default(10),
            offset: z.number()
                .int()
                .min(0)
                .default(0),
        }),

        // File operations with path validation
        'file:read': z.object({
            path: z.string()
                .max(500, 'Path too long')
                // Block absolute paths
                .refine(p => !p.startsWith('/'), 'Absolute paths not allowed')
                // Block path traversal
                .refine(p => !p.includes('..'), 'Path traversal not allowed')
                // Only allow certain extensions
                .refine(
                    p => ['.txt', '.json', '.md'].some(ext => p.endsWith(ext)),
                    'Only .txt, .json, .md files allowed'
                ),
        }),

        // Search with sanitization
        'search:query': z.object({
            query: z.string()
                .min(1, 'Query cannot be empty')
                .max(200, 'Query too long')
                .trim(),  // Automatically trim whitespace
            filters: z.object({
                category: z.string().optional(),
                minPrice: z.number().min(0).optional(),
                maxPrice: z.number().min(0).optional(),
            }).optional(),
        }),
    },

    // Enable verbose logging to see validation in action
    verbose: true,
}));

// ============================================================================
// Register tools
// ============================================================================

forge.tool(
    'user:create',
    {
        schema: z.object({
            name: z.string(),
            email: z.string(),
            age: z.number(),
        }),
        description: 'Create a new user',
    },
    async (args) => {
        // Args are already validated and sanitized by mcp-forge-guard
        console.log('[Tool] Creating user:', args);
        return { success: true, userId: 'usr_123' };
    }
);

forge.tool(
    'db:query',
    {
        schema: z.object({
            table: z.string(),
            limit: z.number().optional(),
            offset: z.number().optional(),
        }),
        description: 'Query the database',
    },
    async (args) => {
        console.log('[Tool] Querying:', args);
        return { rows: [], count: 0 };
    }
);

forge.tool(
    'file:read',
    {
        schema: z.object({ path: z.string() }),
        description: 'Read a file',
    },
    async ({ path }) => {
        console.log('[Tool] Reading file:', path);
        return `Contents of ${path}`;
    }
);

forge.tool(
    'search:query',
    {
        schema: z.object({
            query: z.string(),
            filters: z.object({}).optional(),
        }),
        description: 'Search for items',
    },
    async (args) => {
        console.log('[Tool] Searching:', args);
        return { results: [] };
    }
);

// ============================================================================
// Example calls that would be BLOCKED
// ============================================================================
console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  mcp-forge-guard Example: Parameter Validation                        ║
╠══════════════════════════════════════════════════════════════════╣
║  The guard will BLOCK these malicious inputs:                   ║
║                                                                  ║
║  user:create:                                                    ║
║    - { name: "", ... }              → Name is required           ║
║    - { email: "not-email", ... }    → Invalid email             ║
║    - { age: 10, ... }               → Must be at least 13       ║
║                                                                  ║
║  db:query:                                                       ║
║    - { table: "secrets" }           → Invalid table name         ║
║    - { limit: 10000 }               → Max 100                    ║
║                                                                  ║
║  file:read:                                                      ║
║    - { path: "/etc/passwd" }        → Absolute path blocked      ║
║    - { path: "../../secrets" }      → Path traversal blocked     ║
║    - { path: "script.sh" }          → Extension not allowed      ║
║                                                                  ║
║  Built-in injection detection also blocks:                      ║
║    - Command injection: "; rm -rf /"                             ║
║    - Subshell execution: "$(whoami)"                             ║
║    - Null byte injection: "file.txt\\x00"                        ║
╚══════════════════════════════════════════════════════════════════╝
`);

forge.start();
