/**
 * @fileoverview Unit tests for ApprovalGuard (Human-in-the-Loop Gate).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    createApprovalGuard,
    formatApprovalRequest,
} from '../../src/guards/ApprovalGuard';
import type { ToolCallContext, ApprovalHandler } from '../../src/types';

const createCtx = (
    toolName: string,
    args: Record<string, unknown> = {},
    userPrompt?: string
): ToolCallContext => ({
    toolName,
    args,
    userPrompt,
});

describe('ApprovalGuard', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe('createApprovalGuard', () => {
        it('should allow non-critical tools without approval', async () => {
            const mockHandler: ApprovalHandler = vi.fn();

            const guard = createApprovalGuard({
                criticalTools: ['admin:*', 'fs:delete*'],
                approvalHandler: mockHandler,
            });

            const result = await guard(createCtx('fs:readFile', { path: 'test.txt' }));

            expect(result.allowed).toBe(true);
            expect(mockHandler).not.toHaveBeenCalled();
        });

        it('should require approval for critical tools', async () => {
            const mockHandler: ApprovalHandler = vi.fn().mockResolvedValue(true);

            const guard = createApprovalGuard({
                criticalTools: ['admin:*'],
                approvalHandler: mockHandler,
            });

            const resultPromise = guard(createCtx('admin:deleteUser', { userId: '123' }));
            await vi.runAllTimersAsync();
            const result = await resultPromise;

            expect(result.allowed).toBe(true);
            expect(mockHandler).toHaveBeenCalledOnce();
        });

        it('should deny when approval is rejected', async () => {
            const mockHandler: ApprovalHandler = vi.fn().mockResolvedValue(false);

            const guard = createApprovalGuard({
                criticalTools: ['danger:*'],
                approvalHandler: mockHandler,
            });

            const resultPromise = guard(createCtx('danger:operation', {}));
            await vi.runAllTimersAsync();
            const result = await resultPromise;

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('Approval denied');
        });

        it('should match critical tools with glob patterns', async () => {
            const mockHandler: ApprovalHandler = vi.fn().mockResolvedValue(true);

            const guard = createApprovalGuard({
                criticalTools: ['db:drop*', 'fs:delete*'],
                approvalHandler: mockHandler,
            });

            // Should match
            const resultPromise1 = guard(createCtx('db:dropTable', { table: 'users' }));
            await vi.runAllTimersAsync();
            await resultPromise1;
            expect(mockHandler).toHaveBeenCalledTimes(1);

            const resultPromise2 = guard(createCtx('fs:deleteFile', { path: 'test.txt' }));
            await vi.runAllTimersAsync();
            await resultPromise2;
            expect(mockHandler).toHaveBeenCalledTimes(2);

            // Should not match
            vi.clearAllMocks();
            await guard(createCtx('db:query', { sql: 'SELECT *' }));
            expect(mockHandler).not.toHaveBeenCalled();
        });

        it('should timeout and deny by default', async () => {
            const mockHandler: ApprovalHandler = vi.fn().mockImplementation(
                () => new Promise(() => {
                    // Never resolves
                })
            );

            const guard = createApprovalGuard({
                criticalTools: ['critical:*'],
                approvalHandler: mockHandler,
                timeoutMs: 5000,
                onTimeout: 'deny',
            });

            const resultPromise = guard(createCtx('critical:action', {}));
            await vi.advanceTimersByTimeAsync(5001);
            const result = await resultPromise;

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('timed out');
        });

        it('should timeout and allow when configured', async () => {
            const mockHandler: ApprovalHandler = vi.fn().mockImplementation(
                () => new Promise(() => {
                    // Never resolves
                })
            );

            const guard = createApprovalGuard({
                criticalTools: ['critical:*'],
                approvalHandler: mockHandler,
                timeoutMs: 5000,
                onTimeout: 'allow',
            });

            const resultPromise = guard(createCtx('critical:action', {}));
            await vi.advanceTimersByTimeAsync(5001);
            const result = await resultPromise;

            expect(result.allowed).toBe(true);
        });

        it('should call onApprovalRequested callback', async () => {
            const mockHandler: ApprovalHandler = vi.fn().mockResolvedValue(true);
            const onRequested = vi.fn();

            const guard = createApprovalGuard({
                criticalTools: ['audit:*'],
                approvalHandler: mockHandler,
                onApprovalRequested: onRequested,
            });

            const ctx = createCtx('audit:action', { data: 'test' });
            const resultPromise = guard(ctx);
            await vi.runAllTimersAsync();
            await resultPromise;

            expect(onRequested).toHaveBeenCalledWith(ctx);
        });

        it('should call onApprovalReceived callback', async () => {
            const mockHandler: ApprovalHandler = vi.fn().mockResolvedValue(true);
            const onReceived = vi.fn();

            const guard = createApprovalGuard({
                criticalTools: ['audit:*'],
                approvalHandler: mockHandler,
                onApprovalReceived: onReceived,
            });

            const ctx = createCtx('audit:action', {});
            const resultPromise = guard(ctx);
            await vi.runAllTimersAsync();
            await resultPromise;

            expect(onReceived).toHaveBeenCalledWith(ctx, true);
        });

        it('should handle approval handler errors gracefully', async () => {
            const mockHandler: ApprovalHandler = vi.fn().mockRejectedValue(
                new Error('Slack API unavailable')
            );

            const guard = createApprovalGuard({
                criticalTools: ['critical:*'],
                approvalHandler: mockHandler,
            });

            const resultPromise = guard(createCtx('critical:action', {}));
            await vi.runAllTimersAsync();
            const result = await resultPromise;

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('Approval process failed');
        });
    });

    describe('formatApprovalRequest', () => {
        it('should format request with all details', () => {
            const ctx = createCtx(
                'admin:deleteUser',
                { userId: '123', reason: 'test' },
                'Delete the test user'
            );

            const formatted = formatApprovalRequest(ctx);

            expect(formatted).toContain('APPROVAL REQUIRED');
            expect(formatted).toContain('admin:deleteUser');
            expect(formatted).toContain('userId');
            expect(formatted).toContain('123');
            expect(formatted).toContain('Delete the test user');
        });

        it('should handle missing user prompt', () => {
            const ctx = createCtx('admin:action', { data: 'test' });

            const formatted = formatApprovalRequest(ctx);

            expect(formatted).toContain('admin:action');
            expect(formatted).not.toContain('Original User Request');
        });
    });

    describe('security scenarios', () => {
        it('should not allow bypassing approval through timing', async () => {
            let resolveApproval: (value: boolean) => void;
            const mockHandler: ApprovalHandler = vi.fn().mockImplementation(
                () => new Promise<boolean>(resolve => {
                    resolveApproval = resolve;
                })
            );

            const guard = createApprovalGuard({
                criticalTools: ['danger:*'],
                approvalHandler: mockHandler,
                timeoutMs: 10000,
            });

            // Start the approval process
            const resultPromise = guard(createCtx('danger:action', {}));

            // Approval hasn't been granted yet
            await vi.advanceTimersByTimeAsync(100);

            // Resolve with false (denied)
            resolveApproval!(false);
            await vi.runAllTimersAsync();

            const result = await resultPromise;
            expect(result.allowed).toBe(false);
        });

        it('should protect against concurrent approval bypass', async () => {
            const mockHandler: ApprovalHandler = vi.fn()
                .mockResolvedValueOnce(true)
                .mockResolvedValueOnce(false);

            const guard = createApprovalGuard({
                criticalTools: ['danger:*'],
                approvalHandler: mockHandler,
            });

            // Two concurrent requests - each should be evaluated independently
            const promise1 = guard(createCtx('danger:action1', {}));
            const promise2 = guard(createCtx('danger:action2', {}));

            await vi.runAllTimersAsync();

            const result1 = await promise1;
            const result2 = await promise2;

            expect(result1.allowed).toBe(true);
            expect(result2.allowed).toBe(false);
            expect(mockHandler).toHaveBeenCalledTimes(2);
        });
    });
});
