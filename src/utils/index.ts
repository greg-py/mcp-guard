/**
 * @fileoverview Utility module exports.
 */

export {
    matchPattern,
    extractNamespace,
    matchesAnyPattern,
} from './patterns.js';

export {
    pipe,
    when,
    unless,
    withContext,
    allow,
    deny,
    safe,
} from './compose.js';
