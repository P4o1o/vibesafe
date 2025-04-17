import { FindingSeverity } from './dependencies'; // Re-use severity type

export interface EndpointFinding {
    file: string;
    line: number; // Line where the potential endpoint is defined
    path: string; // The matched endpoint path (e.g., '/admin')
    type: 'Potentially Exposed Debug/Admin Endpoint';
    severity: FindingSeverity;
    message: string;
    details?: string; // Context from the line
}

// Regex patterns for common debug/admin paths
// Includes common framework patterns (like Express) and simple string literals
// - Looks for .get, .post, .put, .delete, .use, .all followed by ('/admin...') or similar
// - Looks for string literals like '/admin', "/debug" etc.
const DEBUG_ADMIN_ENDPOINT_REGEX = /(\.get|\.post|\.put|\.delete|\.use|\.all)\s*\(\s*['"](\/debug|\/admin|\/status|\/info|\/healthz?|\/metrics|\/console|\/manage|\/config)[\/\w\-\:]*['"]/gi;
const DEBUG_ADMIN_STRING_LITERAL_REGEX = /['"](\/debug|\/admin|\/status|\/info|\/healthz?|\/metrics|\/console|\/manage|\/config)[\/\w\-\:]*['"]/gi;


/**
 * Scans file content for potentially exposed debug or admin endpoints.
 * @param filePath Absolute path to the file.
 * @param content The content of the file.
 * @returns An array of EndpointFinding objects.
 */
export function scanForExposedEndpoints(filePath: string, content: string): EndpointFinding[] {
    const findings: EndpointFinding[] = [];
    const lines = content.split('\n');

    let match;

    // Check for framework patterns first (e.g., app.get('/admin'))
    DEBUG_ADMIN_ENDPOINT_REGEX.lastIndex = 0;
    while ((match = DEBUG_ADMIN_ENDPOINT_REGEX.exec(content)) !== null) {
        const fullMatch = match[0];
        const endpointPath = match[2]; // The captured path like '/admin'
        const lineNumber = content.substring(0, match.index).split('\n').length;

        // Avoid adding duplicates for the same line/path if regex matches slightly different parts
        if (!findings.some(f => f.file === filePath && f.line === lineNumber && f.path === endpointPath)) {
            findings.push({
                file: filePath,
                line: lineNumber,
                path: endpointPath,
                type: 'Potentially Exposed Debug/Admin Endpoint',
                severity: 'Medium', // Severity could be adjusted based on path
                message: `Potential debug/admin endpoint found: ${endpointPath}`,
                details: `Found pattern near line ${lineNumber}: ${lines[lineNumber-1].trim().substring(0, 100)}${lines[lineNumber-1].trim().length > 100 ? '...' : ''}`
            });
        }
    }

    // Check for simple string literals as a fallback (lower confidence)
    DEBUG_ADMIN_STRING_LITERAL_REGEX.lastIndex = 0;
    while ((match = DEBUG_ADMIN_STRING_LITERAL_REGEX.exec(content)) !== null) {
        const endpointPath = match[1]; // The captured path like '/admin'
        const lineNumber = content.substring(0, match.index).split('\n').length;

        // Only add if not already found by the more specific framework pattern on the same line
        if (!findings.some(f => f.file === filePath && f.line === lineNumber)) {
            findings.push({
                file: filePath,
                line: lineNumber,
                path: endpointPath,
                type: 'Potentially Exposed Debug/Admin Endpoint',
                severity: 'Low', // Lower severity for simple string matches
                message: `Potential debug/admin endpoint string found: ${endpointPath}`,
                details: `Found string literal near line ${lineNumber}: ${lines[lineNumber-1].trim().substring(0, 100)}${lines[lineNumber-1].trim().length > 100 ? '...' : ''}`
            });
        }
    }

    // Final de-duplication (though the checks above should handle most cases)
    return findings.filter((finding, index, self) =>
        index === self.findIndex((f) => (
            f.file === finding.file && f.line === finding.line && f.path === finding.path && f.severity === finding.severity
        ))
    );
} 