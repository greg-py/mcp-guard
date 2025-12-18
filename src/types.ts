/**
 * @fileoverview Core type definitions for mcp-forge-guard security plugin.
 * 
 * This module defines the fundamental types used throughout the guard system,
 * including tool context, guard results, and provider interfaces.
 */

import type { z } from 'zod';

/**
 * Context passed to each guard during tool call evaluation.
 * Contains all information needed to make security decisions.
 */
export interface ToolCallContext {
    /** The fully-qualified name of the tool being called (e.g., "fs:readFile", "db:query") */
    readonly toolName: string;

    /** The arguments passed to the tool call */
    readonly args: Readonly<Record<string, unknown>>;

    /** The original user prompt that triggered this tool call (if available) */
    readonly userPrompt?: string | undefined;

    /** Additional metadata from the MCP context */
    readonly meta?: Readonly<Record<string, unknown>> | undefined;
}

/**
 * Result returned by a guard after evaluating a tool call.
 */
export interface GuardResult {
    /** Whether the tool call is allowed to proceed */
    readonly allowed: boolean;

    /** Human-readable reason for denial (required when allowed=false) */
    readonly reason?: string;

    /** Sanitized/modified arguments to use instead of the original */
    readonly sanitizedArgs?: Readonly<Record<string, unknown>>;
}

/**
 * A guard function that evaluates a tool call and returns a security decision.
 * Guards are async to support I/O operations like LLM calls or external approvals.
 */
export type Guard = (ctx: ToolCallContext) => Promise<GuardResult>;

/**
 * Provider function for semantic inspection via LLM.
 * Returns true if the tool call aligns with user intent, false otherwise.
 * 
 * @param prompt - The formatted prompt describing the tool call and user context
 * @returns Promise<boolean> - true if intent-aligned, false if suspicious
 */
export type LLMProvider = (prompt: string) => Promise<boolean>;

/**
 * Handler function for human-in-the-loop approval gates.
 * Called when a critical tool requires manual approval before execution.
 * 
 * @param ctx - The tool call context requiring approval
 * @returns Promise<boolean> - true if approved, false if rejected
 */
export type ApprovalHandler = (ctx: ToolCallContext) => Promise<boolean>;

/**
 * Security tier levels for tools, determining which guards are applied.
 */
export type SecurityTier = 'low' | 'medium' | 'high' | 'critical';

/**
 * Action to take when a namespace rule matches.
 */
export type NamespaceAction = 'allow' | 'deny';

/**
 * A namespace firewall rule for pattern-based access control.
 */
export interface NamespaceRule {
    /** Glob-like pattern to match tool names (e.g., "fs:*", "db:write*") */
    readonly pattern: string;

    /** Action to take when this rule matches */
    readonly action: NamespaceAction;

    /** Optional description for documentation/logging */
    readonly description?: string | undefined;
}

/**
 * Per-tool security configuration.
 */
export interface ToolSecurityConfig {
    /** Security tier determining guard strictness */
    readonly tier: SecurityTier;

    /** Zod schema for parameter validation (optional, overrides global) */
    readonly paramSchema?: z.ZodType;

    /** Whether this tool requires approval gate */
    readonly requiresApproval?: boolean;
}

/**
 * Main configuration for the mcp-forge-guard plugin.
 */
export interface GuardConfig {
    /** 
     * Namespace firewall rules, evaluated in order.
     * First matching rule wins. If no rules match, default action applies.
     */
    readonly namespaceRules?: readonly NamespaceRule[];

    /** 
     * Default action when no namespace rule matches.
     * @default 'deny' (secure by default)
     */
    readonly defaultNamespaceAction?: NamespaceAction;

    /**
     * Per-tool security configurations.
     * Key is the tool name, value is the security config.
     */
    readonly toolConfigs?: Readonly<Record<string, ToolSecurityConfig>>;

    /**
     * List of tool names that require human approval.
     * These tools will pause execution until approved.
     */
    readonly criticalTools?: readonly string[];

    /**
     * Global Zod schemas for parameter validation.
     * Key is the tool name, value is the Zod schema.
     * Tool-specific schemas in toolConfigs take precedence.
     */
    readonly parameterSchemas?: Readonly<Record<string, z.ZodType>>;

    /**
     * LLM provider for semantic inspection.
     * Required if enableSemanticInspection is true.
     */
    readonly llmProvider?: LLMProvider;

    /**
     * Handler for human-in-the-loop approval.
     * Required if criticalTools has entries.
     */
    readonly approvalHandler?: ApprovalHandler;

    /**
     * Enable Layer 3 semantic inspection via LLM.
     * @default false
     */
    readonly enableSemanticInspection?: boolean;

    /**
     * Timeout for approval requests in milliseconds.
     * @default 300000 (5 minutes)
     */
    readonly approvalTimeoutMs?: number;

    /**
     * Enable verbose logging for debugging.
     * @default false
     */
    readonly verbose?: boolean;
}

/**
 * Error thrown when a guard denies a tool call.
 */
export class GuardDeniedError extends Error {
    public readonly guardName: string;
    public readonly toolName: string;
    public readonly reason: string;

    constructor(guardName: string, toolName: string, reason: string) {
        super(`[mcp-forge-guard] ${guardName} denied tool "${toolName}": ${reason}`);
        this.name = 'GuardDeniedError';
        this.guardName = guardName;
        this.toolName = toolName;
        this.reason = reason;
    }
}

/**
 * Error thrown when approval times out.
 */
export class ApprovalTimeoutError extends Error {
    public readonly toolName: string;
    public readonly timeoutMs: number;

    constructor(toolName: string, timeoutMs: number) {
        super(`[mcp-forge-guard] Approval timed out for tool "${toolName}" after ${timeoutMs}ms`);
        this.name = 'ApprovalTimeoutError';
        this.toolName = toolName;
        this.timeoutMs = timeoutMs;
    }
}
