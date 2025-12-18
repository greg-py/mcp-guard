/**
 * @fileoverview Unit tests for StaticGuard (Layer 1: Namespace Firewall).
 */

import { describe, it, expect } from 'vitest';
import {
    createStaticGuard,
    createAllowList,
    createDenyList,
} from '../../src/guards/StaticGuard';
import type { ToolCallContext } from '../../src/types';

const createCtx = (toolName: string): ToolCallContext => ({
    toolName,
    args: {},
});

describe('StaticGuard', () => {
    describe('createStaticGuard', () => {
        it('should allow tools matching allow rules', async () => {
            const guard = createStaticGuard({
                rules: [
                    { pattern: 'fs:read*', action: 'allow' },
                ],
                defaultAction: 'deny',
            });

            const result = await guard(createCtx('fs:readFile'));
            expect(result.allowed).toBe(true);
        });

        it('should deny tools matching deny rules', async () => {
            const guard = createStaticGuard({
                rules: [
                    { pattern: 'fs:delete*', action: 'deny', description: 'Deletes not allowed' },
                ],
                defaultAction: 'allow',
            });

            const result = await guard(createCtx('fs:deleteFile'));
            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('Deletes not allowed');
        });

        it('should apply first matching rule (order matters)', async () => {
            const guard = createStaticGuard({
                rules: [
                    { pattern: 'fs:readFile', action: 'deny' },
                    { pattern: 'fs:*', action: 'allow' },
                ],
                defaultAction: 'deny',
            });

            // Specific rule takes precedence
            const result1 = await guard(createCtx('fs:readFile'));
            expect(result1.allowed).toBe(false);

            // Fallback to second rule
            const result2 = await guard(createCtx('fs:writeFile'));
            expect(result2.allowed).toBe(true);
        });

        it('should use default action when no rule matches', async () => {
            const guardDeny = createStaticGuard({
                rules: [{ pattern: 'fs:*', action: 'allow' }],
                defaultAction: 'deny',
            });

            const guardAllow = createStaticGuard({
                rules: [{ pattern: 'fs:*', action: 'deny' }],
                defaultAction: 'allow',
            });

            expect((await guardDeny(createCtx('db:query'))).allowed).toBe(false);
            expect((await guardAllow(createCtx('db:query'))).allowed).toBe(true);
        });

        it('should match wildcard patterns correctly', async () => {
            const guard = createStaticGuard({
                rules: [
                    { pattern: '*', action: 'allow' },
                ],
                defaultAction: 'deny',
            });

            expect((await guard(createCtx('anything'))).allowed).toBe(true);
            expect((await guard(createCtx('foo:bar:baz'))).allowed).toBe(true);
        });

        it('should match prefix patterns', async () => {
            const guard = createStaticGuard({
                rules: [
                    { pattern: 'admin:*', action: 'deny' },
                ],
                defaultAction: 'allow',
            });

            expect((await guard(createCtx('admin:deleteUser'))).allowed).toBe(false);
            expect((await guard(createCtx('admin:settings'))).allowed).toBe(false);
            expect((await guard(createCtx('user:profile'))).allowed).toBe(true);
        });

        it('should match suffix patterns', async () => {
            const guard = createStaticGuard({
                rules: [
                    { pattern: '*:delete', action: 'deny' },
                ],
                defaultAction: 'allow',
            });

            expect((await guard(createCtx('fs:delete'))).allowed).toBe(false);
            expect((await guard(createCtx('db:delete'))).allowed).toBe(false);
            expect((await guard(createCtx('fs:read'))).allowed).toBe(true);
        });

        it('should match exact tool names', async () => {
            const guard = createStaticGuard({
                rules: [
                    { pattern: 'specific_tool', action: 'deny' },
                ],
                defaultAction: 'allow',
            });

            expect((await guard(createCtx('specific_tool'))).allowed).toBe(false);
            expect((await guard(createCtx('specific_tool_extra'))).allowed).toBe(true);
        });
    });

    describe('createAllowList', () => {
        it('should allow only listed patterns', async () => {
            const guard = createAllowList(['safe:*', 'public:*']);

            expect((await guard(createCtx('safe:action'))).allowed).toBe(true);
            expect((await guard(createCtx('public:data'))).allowed).toBe(true);
            expect((await guard(createCtx('private:secret'))).allowed).toBe(false);
        });
    });

    describe('createDenyList', () => {
        it('should deny listed patterns and allow others', async () => {
            const guard = createDenyList(['danger:*', 'admin:*']);

            expect((await guard(createCtx('danger:action'))).allowed).toBe(false);
            expect((await guard(createCtx('admin:settings'))).allowed).toBe(false);
            expect((await guard(createCtx('safe:action'))).allowed).toBe(true);
        });
    });

    describe('security scenarios', () => {
        it('should block namespace bypass attempts', async () => {
            const guard = createStaticGuard({
                rules: [
                    { pattern: 'safe:*', action: 'allow' },
                ],
                defaultAction: 'deny',
            });

            // Attempts to bypass with similar names
            expect((await guard(createCtx('safe'))).allowed).toBe(false);
            expect((await guard(createCtx('safer:action'))).allowed).toBe(false);
            expect((await guard(createCtx('unsafe:action'))).allowed).toBe(false);
        });

        it('should handle empty tool names', async () => {
            const guard = createStaticGuard({
                rules: [{ pattern: '*', action: 'allow' }],
                defaultAction: 'deny',
            });

            expect((await guard(createCtx(''))).allowed).toBe(true);
        });
    });
});
