import { FindingSeverity, DependencyInfo } from './dependencies'; // Added DependencyInfo
import fs from 'fs'; // Added fs import
import path from 'path'; // Added path import
import { DetectedTechnologies } from '../frameworkDetection'; // Import DetectedTechnologies

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

// Regex to find common route definitions (e.g., .get('/path'))
const ROUTE_DEFINITION_REGEX = /(\.get|\.post|\.put|\.delete|\.patch|\.all|\.use)\s*\(\s*['"]\/[\w\-\/\:]*['"]/i;
// Regex for conventional API directories (Next.js, etc.) - case insensitive
const CONVENTIONAL_API_DIR_REGEX = /[\/](pages[\/]api|app[\/]api)[\/]/i;

// Removed RATE_LIMIT_IMPORT_REGEX as we now check package.json

/**
 * Checks if known rate-limiting packages are present and if any API routes likely exist.
 * Issues a project-level warning if routes exist but no known package is found.
 * @param dependencies Array of DependencyInfo objects.
 * @param filesToScan Array of file paths (absolute) to check for route definitions.
 * @param detectedTech Object indicating detected technologies (e.g., { hasBackend: true }).
 * @returns An array containing at most one RateLimitFinding object.
 */
export function checkRateLimitHeuristic(dependencies: DependencyInfo[], filesToScan: string[], detectedTech: DetectedTechnologies): RateLimitFinding[] {
    // If no backend framework detected, this heuristic isn't relevant
    if (!detectedTech.hasBackend) {
        return [];
    }

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
        // Check 1: Conventional API directory structure (e.g., Next.js)
        if (CONVENTIONAL_API_DIR_REGEX.test(filePath)) {
            routesExist = true;
            break; // Found routes via directory structure
        }

        // Check 2: Regex for common route definitions in file content
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            ROUTE_DEFINITION_REGEX.lastIndex = 0; // Reset regex state
            if (ROUTE_DEFINITION_REGEX.test(content)) {
                routesExist = true;
                break; // Found routes via content regex
            }
        } catch (error: any) {
            // Ignore read errors
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