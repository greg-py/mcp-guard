/**
 * @fileoverview Pattern matching utilities for namespace firewall.
 * 
 * Provides glob-like pattern matching for tool name access control.
 * Supports wildcards, prefixes, and exact matches.
 */

/**
 * Matches a tool name against a glob-like pattern.
 * 
 * Supported patterns:
 * - "*" - matches everything
 * - "fs:*" - matches any tool starting with "fs:"
 * - "*:read" - matches any tool ending with ":read"
 * - "db:*:write" - matches tools with "db:" prefix and ":write" suffix
 * - "exact_name" - matches only the exact tool name
 * 
 * @param pattern - The glob-like pattern
 * @param toolName - The tool name to test
 * @returns true if the pattern matches the tool name
 * 
 * @example
 * matchPattern("fs:*", "fs:readFile") // true
 * matchPattern("fs:*", "db:query")    // false
 * matchPattern("*:delete", "fs:delete") // true
 * matchPattern("*", "anything")       // true
 */
export function matchPattern(pattern: string, toolName: string): boolean {
    // Universal wildcard
    if (pattern === '*') {
        return true;
    }

    // Exact match (no wildcards)
    if (!pattern.includes('*')) {
        return pattern === toolName;
    }

    // Convert glob pattern to regex
    // Escape special regex characters except *
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');

    // Convert * to regex .*
    const regexPattern = escaped.replace(/\*/g, '.*');

    // Anchor the pattern to match the full string
    const regex = new RegExp(`^${regexPattern}$`);

    return regex.test(toolName);
}

/**
 * Extracts the namespace from a tool name.
 * 
 * Tool names are expected to follow the pattern "namespace:action"
 * or "namespace:sub:action" for nested namespaces.
 * 
 * @param toolName - The fully-qualified tool name
 * @returns The namespace portion, or the full name if no separator found
 * 
 * @example
 * extractNamespace("fs:readFile")     // "fs"
 * extractNamespace("db:users:create") // "db"
 * extractNamespace("simple_tool")     // "simple_tool"
 */
export function extractNamespace(toolName: string): string {
    const separatorIndex = toolName.indexOf(':');
    return separatorIndex === -1 ? toolName : toolName.substring(0, separatorIndex);
}

/**
 * Checks if a tool name matches any pattern in a list.
 * 
 * @param patterns - Array of patterns to check
 * @param toolName - The tool name to test
 * @returns true if any pattern matches
 */
export function matchesAnyPattern(patterns: readonly string[], toolName: string): boolean {
    return patterns.some(pattern => matchPattern(pattern, toolName));
}
