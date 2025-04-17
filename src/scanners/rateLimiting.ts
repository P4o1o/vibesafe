import { FindingSeverity } from './dependencies'; // Re-use severity type

export interface RateLimitFinding {
    file: string;
    line: number; // Line number of a detected route definition
    type: 'Potential Missing Rate Limiting';
    severity: FindingSeverity;
    message: string;
    details?: string; // Context like the route pattern found
}

// Regex to find common route definitions (Express-like)
// Looks for .get, .post, .put, .delete, .patch, .all, .use followed by ('/...')
// This is a simplified pattern
const ROUTE_DEFINITION_REGEX = /(\.get|\.post|\.put|\.delete|\.patch|\.all|\.use)\s*\(\s*['"]\/[\w\-\/\:]*['"]/gi;

// Regex to find imports/requires of express-rate-limit
const RATE_LIMIT_IMPORT_REGEX = /require\(['"]express-rate-limit['"]\)|import .* from ['"]express-rate-limit['"]/g;

/**
 * Scans file content for route definitions where rate limiting might be missing.
 * Issues a finding if routes are found but no 'express-rate-limit' import is detected in the same file.
 * @param filePath Absolute path to the file.
 * @param content The content of the file.
 * @returns An array of RateLimitFinding objects.
 */
export function scanForMissingRateLimit(filePath: string, content: string): RateLimitFinding[] {
    const findings: RateLimitFinding[] = [];
    
    // Reset regex state just in case
    ROUTE_DEFINITION_REGEX.lastIndex = 0;
    RATE_LIMIT_IMPORT_REGEX.lastIndex = 0;

    const hasRouteDefinitions = ROUTE_DEFINITION_REGEX.test(content);
    const hasRateLimitImport = RATE_LIMIT_IMPORT_REGEX.test(content);

    // If routes are defined BUT no rate limit import is found in this file
    if (hasRouteDefinitions && !hasRateLimitImport) {
        // Find the first instance of a route definition for the line number
        ROUTE_DEFINITION_REGEX.lastIndex = 0; // Reset before exec
        const match = ROUTE_DEFINITION_REGEX.exec(content);
        let lineNumber = 1; // Default to 1 if no match found (shouldn't happen if test passed)
        let routeExample = 'N/A';
        
        if (match && match[0]) { // Ensure match and match[0] are not null/undefined
            lineNumber = content.substring(0, match.index).split('\n').length;
             // Check length before substring to avoid errors
            const matchLength = match[0].length;
            routeExample = match[0].substring(0, Math.min(matchLength, 80)) + (matchLength > 80 ? '...' : '');
        }
        
        findings.push({
            file: filePath,
            line: lineNumber, 
            type: 'Potential Missing Rate Limiting',
            severity: 'Low', // Low severity as it's a heuristic check
            message: "Route definitions found without 'express-rate-limit' import in this file.", // Use double quotes
            details: `Consider adding rate limiting (e.g., with express-rate-limit) to protect public or sensitive endpoints defined near line ${lineNumber}. Example route found: ${routeExample}`
        }); // Ensure this object conforms to RateLimitFinding
    }
    // Reset regex state after use
    ROUTE_DEFINITION_REGEX.lastIndex = 0;
    RATE_LIMIT_IMPORT_REGEX.lastIndex = 0;

    return findings; // Ensure function always returns the findings array
} 