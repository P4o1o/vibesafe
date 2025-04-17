import { FindingSeverity } from './dependencies'; // Re-use severity type

export interface ErrorLoggingFinding {
    file: string;
    line: number; // Line where the potential improper logging occurs
    type: 'Potential Unsanitized Error Logging';
    severity: FindingSeverity;
    message: string;
    details?: string; // Context from the line or logged variable
}

// Regex to find common logging methods called with common error variable names
// Looks for console.log/error/warn or logger.log/error/warn followed by (err), (error), or (e)
// This is a heuristic and might miss cases or have false positives (e.g., logging a variable named 'e' that isn't an error)
const IMPROPER_ERROR_LOGGING_REGEX = /(console|logger)\.(log|error|warn|debug|info)\s*\(\s*(err|error|e)\s*\)/gi;

/**
 * Scans file content for potential logging of full error objects.
 * @param filePath Absolute path to the file.
 * @param content The content of the file.
 * @returns An array of ErrorLoggingFinding objects.
 */
export function scanForImproperErrorLogging(filePath: string, content: string): ErrorLoggingFinding[] {
    const findings: ErrorLoggingFinding[] = [];
    const lines = content.split('\n');
    let match;

    IMPROPER_ERROR_LOGGING_REGEX.lastIndex = 0; // Reset regex state

    while ((match = IMPROPER_ERROR_LOGGING_REGEX.exec(content)) !== null) {
        const fullMatch = match[0];
        const loggerMethod = `${match[1]}.${match[2]}`; // e.g., console.error
        const errorVariable = match[3]; // e.g., err
        const lineNumber = content.substring(0, match.index).split('\n').length;

        // Avoid duplicates on the same line if regex somehow matches multiple times
        if (!findings.some(f => f.file === filePath && f.line === lineNumber)) {
            findings.push({
                file: filePath,
                line: lineNumber,
                type: 'Potential Unsanitized Error Logging',
                severity: 'Low', // Low severity, as context is needed to confirm if it's an issue
                message: `Potential logging of unsanitized error object/stack trace using variable '${errorVariable}'.`,
                details: `Found call to ${loggerMethod}(${errorVariable}) near line ${lineNumber}: ${lines[lineNumber-1].trim().substring(0, 100)}...`
            });
        }
    }

    IMPROPER_ERROR_LOGGING_REGEX.lastIndex = 0; // Reset regex state after use
    return findings;
} 