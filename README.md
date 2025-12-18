# mcp-guard

[![npm version](https://badge.fury.io/js/mcp-guard.svg)](https://www.npmjs.com/package/mcp-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A multi-layered security middleware plugin for [mcp-forge](https://github.com/greg-py/mcp-forge) that provides defense-in-depth protection for MCP tool calls.

## Features

- 🔐 **Namespace Firewall** — Pattern-based access control for tool namespaces
- 🛡️ **Parameter Validation** — Zod-based argument scrubbing with injection prevention
- 🧠 **Semantic Inspection** — LLM-powered intent-alignment verification
- ✋ **Human-in-the-Loop** — Approval gates for critical operations
- ⚡ **High Performance** — Minimal latency overhead with lazy guard evaluation
- 🧩 **Modular Design** — Use only the guards you need

## Installation

```bash
npm install mcp-guard mcp-forge zod
```

## Quick Start

```typescript
import { Forge } from 'mcp-forge';
import { mcpGuard } from 'mcp-guard';
import { z } from 'zod';

const forge = new Forge({ name: 'secure-server', version: '1.0.0' });

// Add the security guard
forge.plugin(mcpGuard({
  // Layer 1: Namespace Firewall
  namespaceRules: [
    { pattern: 'public:*', action: 'allow' },
    { pattern: 'fs:read*', action: 'allow' },
    { pattern: 'fs:*', action: 'deny' },
  ],
  
  // Layer 2: Parameter Validation
  parameterSchemas: {
    'fs:readFile': z.object({
      path: z.string().max(500).refine(
        p => !p.includes('..'), 
        'Path traversal not allowed'
      ),
    }),
  },
  
  // Layer 3: Semantic Inspection (optional)
  enableSemanticInspection: true,
  llmProvider: async (prompt) => {
    const response = await yourLLM(prompt);
    return response.includes('ALIGNED');
  },
  
  // Layer 4: Approval Gate (optional)
  criticalTools: ['admin:*', 'db:drop*'],
  approvalHandler: async (ctx) => {
    return await requestSlackApproval(ctx);
  },
}));

// Register your tools
forge.tool('public:hello', { /* ... */ }, () => 'Hello!');
forge.tool('fs:readFile', { /* ... */ }, ({ path }) => readFile(path));

forge.start();
```

## Guard Layers

mcp-guard implements a multi-layered defense strategy:

### Layer 1: Static Guard (Namespace Firewall)

Pattern-based access control using glob-like patterns:

```typescript
{
  namespaceRules: [
    { pattern: 'safe:*', action: 'allow' },
    { pattern: 'fs:read*', action: 'allow' },
    { pattern: 'fs:write*', action: 'deny', description: 'Write operations blocked' },
    { pattern: 'admin:*', action: 'deny' },
  ],
  defaultNamespaceAction: 'deny', // secure by default
}
```

Supported patterns:
- `*` — matches everything
- `fs:*` — matches any tool starting with `fs:`
- `*:delete` — matches any tool ending with `:delete`
- `exact_name` — matches only that exact tool

### Layer 2: Validation Guard (Parameter Scrubbing)

Zod-based validation with automatic injection detection:

```typescript
{
  parameterSchemas: {
    'user:create': z.object({
      name: z.string().min(1).max(100),
      email: z.string().email(),
    }),
    'db:query': z.object({
      sql: z.string().refine(
        s => !s.toUpperCase().includes('DROP'),
        'DROP statements not allowed'
      ),
    }),
  },
}
```

Built-in protection against:
- Command injection (`; rm -rf /`, backticks, `$()`)
- Path traversal (`../../../etc/passwd`)
- Null byte injection
- Template injection (`{{...}}`)

### Layer 3: Semantic Guard (Intent Verification)

LLM-powered verification that tool calls align with user intent:

```typescript
{
  enableSemanticInspection: true,
  llmProvider: async (prompt) => {
    // Call your LLM with the inspection prompt
    // Return true if the action aligns with user intent
    const response = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: prompt }],
    });
    return response.choices[0].message.content?.includes('ALIGNED') ?? false;
  },
}
```

### Layer 4: Approval Guard (Human-in-the-Loop)

Async approval gates for critical operations:

```typescript
{
  criticalTools: ['admin:deleteUser', 'db:drop*', 'billing:*'],
  approvalHandler: async (ctx) => {
    // Notify and wait for human approval
    const approved = await slack.requestApproval({
      channel: '#security-approvals',
      message: `Tool: ${ctx.toolName}\nArgs: ${JSON.stringify(ctx.args)}`,
    });
    return approved;
  },
  approvalTimeoutMs: 300_000, // 5 minutes
}
```

## Advanced Usage

### Custom Guard Composition

Use functional composition for advanced guard logic:

```typescript
import { 
  createStaticGuard, 
  createValidationGuard,
  pipe, 
  when 
} from 'mcp-guard';

// Create custom guards
const namespaceGuard = createStaticGuard({
  rules: [{ pattern: 'api:*', action: 'allow' }],
});

const validationGuard = createValidationGuard({
  schemas: { 'api:query': z.object({ id: z.string().uuid() }) },
});

// Compose them
const customPipeline = pipe(namespaceGuard, validationGuard);
```

### Conditional Guards

Apply guards conditionally:

```typescript
import { when, createApprovalGuard } from 'mcp-guard';

const conditionalApproval = when(
  // Only require approval during business hours
  (ctx) => {
    const hour = new Date().getHours();
    return hour >= 9 && hour <= 17;
  },
  createApprovalGuard({
    criticalTools: ['*'],
    approvalHandler: async () => true,
  })
);
```

### Allow/Deny Lists

Simple shortcuts for common patterns:

```typescript
import { createAllowList, createDenyList } from 'mcp-guard';

// Only allow specific tools
const allowList = createAllowList(['safe:*', 'public:*']);

// Block specific tools, allow everything else
const denyList = createDenyList(['danger:*', 'admin:*']);
```

## Configuration Reference

```typescript
interface GuardConfig {
  // Layer 1: Namespace Firewall
  namespaceRules?: NamespaceRule[];
  defaultNamespaceAction?: 'allow' | 'deny'; // default: 'deny'
  
  // Layer 2: Parameter Validation
  parameterSchemas?: Record<string, z.ZodType>;
  
  // Layer 3: Semantic Inspection
  enableSemanticInspection?: boolean; // default: false
  llmProvider?: (prompt: string) => Promise<boolean>;
  
  // Layer 4: Approval Gate
  criticalTools?: string[];
  approvalHandler?: (ctx: ToolCallContext) => Promise<boolean>;
  approvalTimeoutMs?: number; // default: 300000 (5 min)
  
  // Debugging
  verbose?: boolean; // default: false
}

interface NamespaceRule {
  pattern: string;
  action: 'allow' | 'deny';
  description?: string;
}
```

## Error Handling

mcp-guard throws specific errors that you can catch:

```typescript
import { GuardDeniedError, ApprovalTimeoutError } from 'mcp-guard';

try {
  await forge.simulateToolCall('blocked:action', {});
} catch (error) {
  if (error instanceof GuardDeniedError) {
    console.log(`Denied by: ${error.guardName}`);
    console.log(`Tool: ${error.toolName}`);
    console.log(`Reason: ${error.reason}`);
  }
  
  if (error instanceof ApprovalTimeoutError) {
    console.log(`Approval timed out for: ${error.toolName}`);
  }
}
```

## Best Practices

1. **Deny by Default** — Set `defaultNamespaceAction: 'deny'` and explicitly allow trusted tools
2. **Layer Defense** — Use multiple guard layers; don't rely on just one
3. **Validate Early** — Put strict validation schemas on all tools that accept user input
4. **Log Denials** — Enable `verbose: true` in development to understand guard behavior
5. **Test Thoroughly** — Write tests for edge cases and injection attempts

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE) © 2025 Greg King
