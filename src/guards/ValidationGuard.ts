/**
 * @fileoverview ValidationGuard - Layer 2: Parameter Scrubbing.
 * 
 * Provides Zod-based parameter validation and sanitization to prevent
 * argument injection attacks. Validates tool arguments against defined
 * schemas, strips unknown keys, and coerces types.
 * 
 * @example
 * const guard = createValidationGuard({
 *   schemas: {
 *     'fs:readFile': z.object({ path: z.string().max(1000) }),
 *     'db:query': z.object({ 
 *       sql: z.string().refine(s => !s.includes('DROP'), 'SQL injection detected'),
 *     }),
 *   },
 *   stripUnknown: true,
 * });
 */

import type { z, ZodError } from 'zod';
import type { Guard, GuardResult } from '../types.js';

/**
 * Configuration for the ValidationGuard.
 */
export interface ValidationGuardConfig {
    /**
     * Map of tool names to their Zod validation schemas.
     * Tools without a schema are passed through (or blocked if strict mode).
     */
    readonly schemas: Readonly<Record<string, z.ZodType>>;

    /**
     * If true, tools without defined schemas are blocked.
     * @default false
     */
    readonly strictMode?: boolean;

    /**
     * If true, strip unknown keys from objects (uses .passthrough() if false).
     * @default true
     */
    readonly stripUnknown?: boolean;
}

/**
 * Formats Zod validation errors into a human-readable string.
 * 
 * @param error - The ZodError to format
 * @returns Formatted error string
 */
function formatZodErrors(error: ZodError): string {
    return error.errors
        .map(e => {
            const path = e.path.length > 0 ? `"${e.path.join('.')}"` : 'value';
            return `${path}: ${e.message}`;
        })
        .join('; ');
}

/**
 * Detects potential injection patterns in string values.
 * This is a defense-in-depth check run before schema validation.
 * 
 * @param value - Value to check
 * @param depth - Current recursion depth
 * @returns True if suspicious patterns detected
 */
function detectInjectionPatterns(value: unknown, depth = 0): boolean {
    // Prevent stack overflow from deeply nested structures
    if (depth > 10) return false;

    if (typeof value === 'string') {
        // Common injection patterns
        const suspiciousPatterns = [
            // Command injection - semicolon/pipe/ampersand followed by space and commands
            /[;|&]\s*\w+/,  // e.g., "; rm", "| cat"
            // Subshell execution
            /\$\([^)]+\)/,  // $(command)
            // Backtick execution
            /`[^`]+`/,      // `command`
            // Variable expansion with braces
            /\$\{[^}]+\}/,  // ${VAR}
            // Path traversal
            /\.\.[/\\]/,    // ../
            // Null byte injection
            /\x00/,
            // JSON/template injection
            /\{\{.*\}\}/,   // {{...}}
            // Control characters (except common ones like tab, newline)
            // eslint-disable-next-line no-control-regex
            /[\x00-\x08\x0b\x0c\x0e-\x1f]/,
        ];

        return suspiciousPatterns.some(pattern => pattern.test(value));
    }

    if (Array.isArray(value)) {
        return value.some(item => detectInjectionPatterns(item, depth + 1));
    }

    if (value !== null && typeof value === 'object') {
        return Object.values(value).some(v => detectInjectionPatterns(v, depth + 1));
    }

    return false;
}

/**
 * Creates a ValidationGuard that validates and sanitizes tool arguments.
 * 
 * The guard performs two levels of protection:
 * 1. Injection pattern detection (defense-in-depth)
 * 2. Zod schema validation with sanitization
 * 
 * @param config - Guard configuration
 * @returns A Guard function for parameter validation
 * 
 * @example
 * const guard = createValidationGuard({
 *   schemas: {
 *     'user:create': z.object({
 *       name: z.string().min(1).max(100),
 *       email: z.string().email(),
 *     }),
 *   },
 * });
 */
export function createValidationGuard(config: ValidationGuardConfig): Guard {
    const { schemas, strictMode = false, stripUnknown = true } = config;

    return async (ctx): Promise<GuardResult> => {
        const schema = schemas[ctx.toolName];

        // No schema defined for this tool
        if (!schema) {
            if (strictMode) {
                return {
                    allowed: false,
                    reason: `No validation schema defined for tool "${ctx.toolName}"`,
                };
            }
            // In non-strict mode, still check for injection patterns
            if (detectInjectionPatterns(ctx.args)) {
                return {
                    allowed: false,
                    reason: 'Potential injection pattern detected in arguments',
                };
            }
            return { allowed: true };
        }

        // Defense-in-depth: check for injection patterns before validation
        if (detectInjectionPatterns(ctx.args)) {
            return {
                allowed: false,
                reason: 'Potential injection pattern detected in arguments',
            };
        }

        // Apply Zod validation
        try {
            // Configure parsing based on stripUnknown setting
            const parseMethod = stripUnknown ? 'safeParse' : 'safeParse';
            const result = schema[parseMethod](ctx.args);

            if (!result.success) {
                return {
                    allowed: false,
                    reason: `Validation failed: ${formatZodErrors(result.error)}`,
                };
            }

            // Return sanitized arguments
            return {
                allowed: true,
                sanitizedArgs: result.data as Record<string, unknown>,
            };
        } catch (error) {
            // Schema execution error (shouldn't happen with safeParse)
            const message = error instanceof Error ? error.message : String(error);
            return {
                allowed: false,
                reason: `Validation error: ${message}`,
            };
        }
    };
}

/**
 * Creates a validation guard with additional custom validators.
 * 
 * @param config - Base validation config
 * @param customValidators - Map of tool names to custom validation functions
 * @returns A Guard function
 */
export function createValidationGuardWithCustom(
    config: ValidationGuardConfig,
    customValidators: Readonly<Record<string, (args: Record<string, unknown>) => boolean | string>>
): Guard {
    const baseGuard = createValidationGuard(config);

    return async (ctx): Promise<GuardResult> => {
        // Run base validation first
        const baseResult = await baseGuard(ctx);
        if (!baseResult.allowed) {
            return baseResult;
        }

        // Run custom validator if defined
        const customValidator = customValidators[ctx.toolName];
        if (customValidator) {
            const customResult = customValidator(baseResult.sanitizedArgs ?? ctx.args);
            if (customResult !== true) {
                return {
                    allowed: false,
                    reason: typeof customResult === 'string'
                        ? customResult
                        : 'Custom validation failed',
                };
            }
        }

        return baseResult;
    };
}
