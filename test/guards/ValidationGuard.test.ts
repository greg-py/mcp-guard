/**
 * @fileoverview Unit tests for ValidationGuard (Layer 2: Parameter Scrubbing).
 * 
 * These tests simulate various malicious argument injection scenarios
 * to ensure the guard properly validates and sanitizes inputs.
 */

import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import {
    createValidationGuard,
    createValidationGuardWithCustom,
} from '../../src/guards/ValidationGuard';
import type { ToolCallContext } from '../../src/types';

const createCtx = (
    toolName: string,
    args: Record<string, unknown>
): ToolCallContext => ({
    toolName,
    args,
});

describe('ValidationGuard', () => {
    describe('schema validation', () => {
        it('should allow valid arguments', async () => {
            const guard = createValidationGuard({
                schemas: {
                    'user:create': z.object({
                        name: z.string(),
                        age: z.number().int().positive(),
                    }),
                },
            });

            const result = await guard(createCtx('user:create', {
                name: 'Alice',
                age: 25,
            }));

            expect(result.allowed).toBe(true);
            expect(result.sanitizedArgs).toEqual({ name: 'Alice', age: 25 });
        });

        it('should reject invalid arguments', async () => {
            const guard = createValidationGuard({
                schemas: {
                    'user:create': z.object({
                        name: z.string().min(1),
                        email: z.string().email(),
                    }),
                },
            });

            const result = await guard(createCtx('user:create', {
                name: '',
                email: 'not-an-email',
            }));

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('Validation failed');
        });

        it('should strip unknown fields from objects', async () => {
            const guard = createValidationGuard({
                schemas: {
                    'data:process': z.object({
                        allowed: z.string(),
                    }).strict(),
                },
                stripUnknown: true,
            });

            const result = await guard(createCtx('data:process', {
                allowed: 'value',
                malicious: 'injection',
            }));

            // With strict(), unknown keys should fail validation
            expect(result.allowed).toBe(false);
        });

        it('should pass through tools without schemas (non-strict mode)', async () => {
            const guard = createValidationGuard({
                schemas: {},
                strictMode: false,
            });

            const result = await guard(createCtx('unknown:tool', { any: 'args' }));
            expect(result.allowed).toBe(true);
        });

        it('should block tools without schemas in strict mode', async () => {
            const guard = createValidationGuard({
                schemas: {},
                strictMode: true,
            });

            const result = await guard(createCtx('unknown:tool', { any: 'args' }));
            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('No validation schema defined');
        });
    });

    describe('injection prevention', () => {
        it('should detect command injection patterns', async () => {
            const guard = createValidationGuard({
                schemas: {},
                strictMode: false,
            });

            // Command injection with subshell
            const result1 = await guard(createCtx('fs:read', {
                path: 'file.txt; rm -rf /',
            }));
            expect(result1.allowed).toBe(false);
            expect(result1.reason).toContain('injection pattern');

            // Command injection with backticks
            const result2 = await guard(createCtx('fs:read', {
                path: '`cat /etc/passwd`',
            }));
            expect(result2.allowed).toBe(false);

            // Command injection with $()
            const result3 = await guard(createCtx('fs:read', {
                path: '$(whoami)',
            }));
            expect(result3.allowed).toBe(false);
        });

        it('should detect path traversal attempts', async () => {
            const guard = createValidationGuard({
                schemas: {},
                strictMode: false,
            });

            const result = await guard(createCtx('fs:read', {
                path: '../../../etc/passwd',
            }));

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('injection pattern');
        });

        it('should detect null byte injection', async () => {
            const guard = createValidationGuard({
                schemas: {},
                strictMode: false,
            });

            const result = await guard(createCtx('fs:read', {
                path: 'file.txt\x00.jpg',
            }));

            expect(result.allowed).toBe(false);
        });

        it('should detect template injection', async () => {
            const guard = createValidationGuard({
                schemas: {},
                strictMode: false,
            });

            const result = await guard(createCtx('template:render', {
                content: '{{ constructor.constructor("return process")().exit() }}',
            }));

            expect(result.allowed).toBe(false);
        });

        it('should detect injection in nested objects', async () => {
            const guard = createValidationGuard({
                schemas: {},
                strictMode: false,
            });

            const result = await guard(createCtx('data:save', {
                user: {
                    name: 'test',
                    bio: 'Hello; rm -rf /',
                },
            }));

            expect(result.allowed).toBe(false);
        });

        it('should detect injection in arrays', async () => {
            const guard = createValidationGuard({
                schemas: {},
                strictMode: false,
            });

            const result = await guard(createCtx('data:batch', {
                items: ['safe', '$(malicious)', 'also-safe'],
            }));

            expect(result.allowed).toBe(false);
        });

        it('should allow safe strings with special characters', async () => {
            const guard = createValidationGuard({
                schemas: {},
                strictMode: false,
            });

            // Single special character is fine
            const result = await guard(createCtx('search:query', {
                query: 'hello world!',
            }));

            expect(result.allowed).toBe(true);
        });
    });

    describe('custom validators', () => {
        it('should run custom validators after schema validation', async () => {
            const guard = createValidationGuardWithCustom(
                {
                    schemas: {
                        'db:query': z.object({ sql: z.string() }),
                    },
                },
                {
                    'db:query': (args) => {
                        const sql = args['sql'] as string;
                        if (sql.toUpperCase().includes('DROP')) {
                            return 'SQL injection: DROP not allowed';
                        }
                        return true;
                    },
                }
            );

            const validResult = await guard(createCtx('db:query', {
                sql: 'SELECT * FROM users',
            }));
            expect(validResult.allowed).toBe(true);

            const invalidResult = await guard(createCtx('db:query', {
                sql: 'DROP TABLE users',
            }));
            expect(invalidResult.allowed).toBe(false);
            expect(invalidResult.reason).toContain('DROP not allowed');
        });
    });

    describe('complex validation scenarios', () => {
        it('should validate with transforms', async () => {
            const guard = createValidationGuard({
                schemas: {
                    'user:create': z.object({
                        email: z.string().email().toLowerCase(),
                        name: z.string().trim(),
                    }),
                },
            });

            const result = await guard(createCtx('user:create', {
                email: 'USER@EXAMPLE.COM',
                name: '  Alice  ',
            }));

            expect(result.allowed).toBe(true);
            expect(result.sanitizedArgs).toEqual({
                email: 'user@example.com',
                name: 'Alice',
            });
        });

        it('should validate with refinements', async () => {
            const guard = createValidationGuard({
                schemas: {
                    'payment:process': z.object({
                        amount: z.number().refine(a => a > 0 && a <= 10000, {
                            message: 'Amount must be between 0 and 10000',
                        }),
                    }),
                },
            });

            const validResult = await guard(createCtx('payment:process', {
                amount: 100,
            }));
            expect(validResult.allowed).toBe(true);

            const invalidResult = await guard(createCtx('payment:process', {
                amount: 999999,
            }));
            expect(invalidResult.allowed).toBe(false);
            expect(invalidResult.reason).toContain('Amount must be');
        });
    });
});
