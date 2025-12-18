# mcp-guard Examples

This directory contains comprehensive examples demonstrating mcp-guard usage with mcp-forge.

## Running Examples

```bash
# Install dependencies
npm install

# Run an example
npx ts-node examples/01-basic-namespace-firewall.ts
```

## Examples

### [01-basic-namespace-firewall.ts](./01-basic-namespace-firewall.ts)

**Difficulty**: Beginner

The simplest use case — using glob patterns to allow/deny tools by namespace:

```typescript
forge.plugin(mcpGuard({
  namespaceRules: [
    { pattern: 'fs:read*', action: 'allow' },
    { pattern: 'fs:*', action: 'deny' },
  ],
}));
```

---

### [02-parameter-validation.ts](./02-parameter-validation.ts)

**Difficulty**: Intermediate

Layer 2 in action — Zod schemas for parameter validation with built-in injection detection:

```typescript
forge.plugin(mcpGuard({
  parameterSchemas: {
    'user:create': z.object({
      name: z.string().min(1).max(100),
      email: z.string().email(),
    }),
    'file:read': z.object({
      path: z.string()
        .refine(p => !p.includes('..'), 'Path traversal blocked'),
    }),
  },
}));
```

---

### [03-full-defense-in-depth.ts](./03-full-defense-in-depth.ts)

**Difficulty**: Advanced

All 4 layers working together:
- Namespace firewall
- Parameter validation
- LLM semantic inspection
- Human-in-the-loop approval

---

### [04-custom-guard-composition.ts](./04-custom-guard-composition.ts)

**Difficulty**: Expert

Creating custom guards and composing them with functional utilities:

```typescript
const pipeline = pipe(
  auditGuard,
  namespaceGuard,
  when(ctx => ctx.toolName.startsWith('api:'), businessHoursGuard),
  validationGuard,
);
```

## Guard Layers Reference

| Layer | Purpose | Config Key |
|-------|---------|------------|
| 1 | Namespace Firewall | `namespaceRules` |
| 2 | Parameter Validation | `parameterSchemas` |
| 3 | Semantic Inspection | `llmProvider` + `enableSemanticInspection` |
| 4 | Approval Gate | `criticalTools` + `approvalHandler` |
