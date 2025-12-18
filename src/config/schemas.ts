/**
 * @fileoverview Zod schemas for type-safe mcp-forge-guard configuration.
 * 
 * These schemas provide runtime validation and type inference for
 * guard configuration, ensuring correct usage at both compile and runtime.
 */

import { z } from 'zod';

/**
 * Schema for namespace firewall action.
 */
export const NamespaceActionSchema = z.enum(['allow', 'deny']);

/**
 * Schema for security tier levels.
 */
export const SecurityTierSchema = z.enum(['low', 'medium', 'high', 'critical']);

/**
 * Schema for a namespace firewall rule.
 */
export const NamespaceRuleSchema = z.object({
    /** Glob-like pattern to match tool names */
    pattern: z.string().min(1, 'Pattern cannot be empty'),
    /** Action to take when rule matches */
    action: NamespaceActionSchema,
    /** Optional description */
    description: z.string().optional(),
}).readonly();

/**
 * Schema for per-tool security configuration.
 */
export const ToolSecurityConfigSchema = z.object({
    tier: SecurityTierSchema,
    // Note: Zod schemas can't be validated by Zod itself, so we use z.any()
    paramSchema: z.any().optional(),
    requiresApproval: z.boolean().optional(),
}).readonly();

/**
 * Schema for the main guard configuration.
 * Provides sensible defaults for security-first operation.
 */
export const GuardConfigSchema = z.object({
    namespaceRules: z.array(NamespaceRuleSchema).readonly().optional(),
    defaultNamespaceAction: NamespaceActionSchema.default('deny'),
    toolConfigs: z.record(z.string(), ToolSecurityConfigSchema).optional(),
    criticalTools: z.array(z.string()).readonly().optional(),
    parameterSchemas: z.record(z.string(), z.any()).optional(),
    llmProvider: z.function()
        .args(z.string())
        .returns(z.promise(z.boolean()))
        .optional(),
    approvalHandler: z.function()
        .args(z.any())
        .returns(z.promise(z.boolean()))
        .optional(),
    enableSemanticInspection: z.boolean().default(false),
    approvalTimeoutMs: z.number().positive().default(300_000), // 5 minutes
    verbose: z.boolean().default(false),
}).readonly();

/**
 * Inferred TypeScript type from the configuration schema.
 */
export type ValidatedGuardConfig = z.infer<typeof GuardConfigSchema>;

/**
 * Validates and normalizes guard configuration with defaults.
 * 
 * @param config - Raw configuration object
 * @returns Validated configuration with defaults applied
 * @throws ZodError if configuration is invalid
 */
export function validateConfig(config: unknown): ValidatedGuardConfig {
    return GuardConfigSchema.parse(config);
}

/**
 * Safely validates configuration without throwing.
 * 
 * @param config - Raw configuration object
 * @returns Result object with success flag and data or error
 */
export function safeValidateConfig(config: unknown): z.SafeParseReturnType<unknown, ValidatedGuardConfig> {
    return GuardConfigSchema.safeParse(config);
}
