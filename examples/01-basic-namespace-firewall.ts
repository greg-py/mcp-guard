/**
 * @fileoverview Basic Example - Namespace Firewall
 * 
 * This example demonstrates the simplest use case: using mcp-forge-guard
 * to restrict tool access by namespace patterns.
 * 
 * Run: npx ts-node examples/01-basic-namespace-firewall.ts
 */

import { Forge } from 'mcp-forge';
import { z } from 'zod';
import { mcpGuard } from 'mcp-forge-guard';

// Create a new MCP server
const forge = new Forge({
    name: 'secure-file-server',
    version: '1.0.0',
});

// ============================================================================
// Add mcp-forge-guard with namespace rules
// ============================================================================
forge.plugin(mcpGuard({
    namespaceRules: [
        // Allow all read operations
        { pattern: 'fs:read*', action: 'allow', description: 'Allow file reads' },
        { pattern: 'fs:list*', action: 'allow', description: 'Allow directory listing' },

        // Block all other fs operations (writes, deletes, etc.)
        { pattern: 'fs:*', action: 'deny', description: 'Block all other fs operations' },

        // Allow public tools
        { pattern: 'public:*', action: 'allow' },
    ],

    // Deny by default - secure by default
    defaultNamespaceAction: 'deny',
}));

// ============================================================================
// Register tools - the guard will protect these automatically
// ============================================================================

// This will be ALLOWED (matches 'fs:read*')
forge.tool(
    'fs:readFile',
    {
        schema: z.object({ path: z.string() }),
        description: 'Read a file from disk',
    },
    async ({ path }) => {
        console.log(`[Tool] Reading file: ${path}`);
        return `Contents of ${path}`;
    }
);

// This will be ALLOWED (matches 'fs:list*')
forge.tool(
    'fs:listDir',
    {
        schema: z.object({ path: z.string() }),
        description: 'List directory contents',
    },
    async ({ path }) => {
        console.log(`[Tool] Listing directory: ${path}`);
        return ['file1.txt', 'file2.txt'];
    }
);

// This will be DENIED (matches 'fs:*' deny rule)
forge.tool(
    'fs:deleteFile',
    {
        schema: z.object({ path: z.string() }),
        description: 'Delete a file from disk',
    },
    async ({ path }) => {
        console.log(`[Tool] Deleting file: ${path}`);
        return `Deleted ${path}`;
    }
);

// This will be DENIED (no matching rule, default is deny)
forge.tool(
    'admin:shutdown',
    {
        schema: z.object({}),
        description: 'Shutdown the server',
    },
    async () => {
        console.log('[Tool] Shutting down...');
        return 'Server shutdown';
    }
);

// This will be ALLOWED (matches 'public:*')
forge.tool(
    'public:getVersion',
    {
        schema: z.object({}),
        description: 'Get server version',
    },
    async () => {
        return { version: '1.0.0' };
    }
);

// ============================================================================
// Start the server
// ============================================================================
console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  mcp-forge-guard Example: Basic Namespace Firewall                     ║
╠══════════════════════════════════════════════════════════════════╣
║  Allowed tools:                                                  ║
║    - fs:readFile    (matches 'fs:read*')                         ║
║    - fs:listDir     (matches 'fs:list*')                         ║
║    - public:getVersion (matches 'public:*')                      ║
║                                                                  ║
║  Blocked tools:                                                  ║
║    - fs:deleteFile  (matches 'fs:*' deny rule)                   ║
║    - admin:shutdown (no match, default deny)                     ║
╚══════════════════════════════════════════════════════════════════╝
`);

forge.start();
