import { FindingSeverity, DependencyInfo } from './dependencies'; // Added DependencyInfo
import fs from 'fs'; // Added fs import
import path from 'path'; // Added path import

export interface RateLimitFinding {
    // file and line are no longer relevant for the project-level warning
    // file: string;
    // line: number;
    type: 'Project-Level Rate Limit Advisory'; // More specific type
    severity: FindingSeverity;
    message: string;
    details?: string;
}

// List of known rate limiting package names (add more as needed)
const KNOWN_RATE_LIMIT_PACKAGES = new Set([
    'express-rate-limit',
    '@upstash/ratelimit',
    'rate-limiter-flexible',
    'express-slow-down',
    // Add other relevant package names here
]);

// Regex to find common route definitions (Express-like)
// Looks for .get, .post, .put, .delete, .patch, .all, .use followed by ('/...')
const ROUTE_DEFINITION_REGEX = /(\.get|\.post|\.put|\.delete|\.patch|\.all|\.use)\s*\(\s*['"]\/[\w\-\/\:]*['"]/i; // Removed global flag, we only need one match

// Removed RATE_LIMIT_IMPORT_REGEX as we now check package.json

/**
 * Checks if known rate-limiting packages are present in dependencies
 * and if any routes are defined in the specified files.
 * Issues a single project-level warning if routes exist but no known package is found.
 * @param dependencies Array of DependencyInfo objects from parsed package files.
 * @param filesToScan Array of file paths (absolute) to check for route definitions.
 * @returns An array containing at most one RateLimitFinding object.
 */
export function checkRateLimitHeuristic(dependencies: DependencyInfo[], filesToScan: string[]): RateLimitFinding[] {
    // Check if any dependency matches the known rate limit packages
    const hasKnownRateLimitPackage = dependencies.some(dep => 
        KNOWN_RATE_LIMIT_PACKAGES.has(dep.name)
    );

    if (hasKnownRateLimitPackage) {
        // Found a known package, assume rate limiting is handled.
        return []; 
    }

    // No known package found, now check if any routes exist in the codebase
    let routesExist = false;
    for (const filePath of filesToScan) {
        try {
            // Optimization: Limit read size? For now, read full file.
            // Small files are common for routes.
            const content = fs.readFileSync(filePath, 'utf-8');
            ROUTE_DEFINITION_REGEX.lastIndex = 0; // Reset regex state
            if (ROUTE_DEFINITION_REGEX.test(content)) {
                routesExist = true;
                break; // Found routes in one file, no need to check others
            }
        } catch (error: any) {
            // Log warning or ignore? Ignoring for now to avoid console noise.
            // console.warn(`Could not read file ${filePath} for rate limit check: ${error.message}`);
        }
    }

    // If routes exist AND no known rate limit package was found, issue the warning
    if (routesExist) {
        return [{
            // No specific file/line for this project-level warning
            type: 'Project-Level Rate Limit Advisory',
            severity: 'Low',
            message: "Did not detect Rate limit package, ensure your api end points have rate limiting to avoid ddos attacks!", // Updated message
            details: `No known rate-limiting package (${Array.from(KNOWN_RATE_LIMIT_PACKAGES).join(', ')}) found in dependencies, but API routes were detected. Please verify rate limiting is implemented (via a library, custom code, or infrastructure) to protect against abuse.`
        }];
    }

    // No routes found, or a known package exists
    return [];
} 