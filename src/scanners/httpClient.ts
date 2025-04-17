import { parse } from '@typescript-eslint/typescript-estree';
import { TSESTree } from '@typescript-eslint/types';
import { FindingSeverity } from './dependencies';

export interface HttpClientFinding {
    file: string;
    line: number; // Line number where the HTTP client call occurs
    type: 'Potential Missing Timeout' | 'Potential Missing Retry' | 'Missing Request Cancellation'; // Add more types as needed
    severity: FindingSeverity;
    library: 'axios' | 'fetch' | 'got' | 'superagent' | 'request' | 'unknown'; // Library detected
    message: string;
    details?: string; // Context like the function/method called
}

/**
 * Scans file content using AST for HTTP client calls lacking recommended configurations (e.g., timeouts).
 * Currently focuses on detecting missing timeouts in axios, fetch, got, superagent, and request.
 * TODO: Implement retry logic checks.
 * @param filePath Absolute path to the file.
 * @param content The content of the file.
 * @returns An array of HttpClientFinding objects.
 */
export function scanForHttpClientIssues(filePath: string, content: string): HttpClientFinding[] {
    const findings: HttpClientFinding[] = [];
    try {
        const ast = parse(content, { loc: true, range: true, comment: false }); // loc: true gives line/column numbers

        // Simple visitor pattern implementation
        function visit(node: TSESTree.Node | null) {
            if (!node) return;

            if (node.type === TSESTree.AST_NODE_TYPES.CallExpression) {
                checkForHttpClientCall(node, filePath, findings);
            }

            // Recursively visit children
            for (const key in node) {
                // eslint-disable-next-line no-prototype-builtins
                if (node.hasOwnProperty(key)) {
                    const child = (node as any)[key];
                    if (typeof child === 'object' && child !== null) {
                        if (Array.isArray(child)) {
                            child.forEach(visit);
                        } else {
                            visit(child);
                        }
                    }
                }
            }
        }

        visit(ast);

    } catch (error: any) {
        // Ignore parsing errors (e.g., invalid JS/TS) - could log if needed
        // console.warn(`AST Parsing error in ${filePath}: ${error.message}`);
    }

    return findings;
}

// List of known axios methods that make requests
const AXIOS_REQUEST_METHODS = new Set(['request', 'get', 'delete', 'head', 'options', 'post', 'put', 'patch']);
// List of known superagent methods that initiate requests
const SUPERAGENT_REQUEST_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'del', 'head', 'options']);
// List of known got methods that make requests
const GOT_REQUEST_METHODS = new Set(['get', 'post', 'put', 'patch', 'head', 'delete', 'stream']);

/**
 * Checks a CallExpression node to see if it's a known HTTP client call
 * and if it might be missing timeout configurations.
 */
function checkForHttpClientCall(node: TSESTree.CallExpression, filePath: string, findings: HttpClientFinding[]) {
    const callee = node.callee;
    let library: HttpClientFinding['library'] = 'unknown';
    let callDetail = '';
    let missingTimeout = false;
    let line = node.loc.start.line;

    // --- Check for axios --- 
    if (callee.type === TSESTree.AST_NODE_TYPES.MemberExpression && 
        callee.object.type === TSESTree.AST_NODE_TYPES.Identifier && 
        callee.object.name === 'axios' &&
        callee.property.type === TSESTree.AST_NODE_TYPES.Identifier &&
        AXIOS_REQUEST_METHODS.has(callee.property.name)) { 
        library = 'axios';
        callDetail = `axios.${callee.property.name}`;
        const configArg = [...node.arguments].reverse().find(arg => arg.type === TSESTree.AST_NODE_TYPES.ObjectExpression);
        missingTimeout = !configArg || !objectHasProperty(configArg as TSESTree.ObjectExpression, ['timeout', 'signal']);
    } else if (callee.type === TSESTree.AST_NODE_TYPES.Identifier && callee.name === 'axios') {
        library = 'axios';
        callDetail = 'axios';
        let configArg: TSESTree.Node | undefined = undefined;
        if (node.arguments.length === 1 && node.arguments[0].type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             configArg = node.arguments[0]; 
        } else if (node.arguments.length > 1 && node.arguments[1].type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             configArg = node.arguments[1]; 
        }
        missingTimeout = !configArg || !objectHasProperty(configArg as TSESTree.ObjectExpression, ['timeout', 'signal']);
    }
    // --- Check for fetch --- 
    else if (callee.type === TSESTree.AST_NODE_TYPES.Identifier && callee.name === 'fetch') {
        library = 'fetch';
        callDetail = 'fetch';
        const optionsArg = node.arguments[1];
        missingTimeout = !optionsArg || optionsArg.type !== TSESTree.AST_NODE_TYPES.ObjectExpression || !objectHasProperty(optionsArg, ['signal']);
    }
    // --- Check for got --- 
    else if (callee.type === TSESTree.AST_NODE_TYPES.Identifier && callee.name === 'got') {
        library = 'got';
        callDetail = 'got';
        const optionsArg = node.arguments[1]; 
        missingTimeout = !optionsArg || optionsArg.type !== TSESTree.AST_NODE_TYPES.ObjectExpression || !objectHasProperty(optionsArg, ['timeout', 'signal']);
    } else if (callee.type === TSESTree.AST_NODE_TYPES.MemberExpression && 
               callee.object.type === TSESTree.AST_NODE_TYPES.Identifier && 
               callee.object.name === 'got' &&
               callee.property.type === TSESTree.AST_NODE_TYPES.Identifier &&
               GOT_REQUEST_METHODS.has(callee.property.name)) {
         library = 'got';
         callDetail = `got.${callee.property.name}`;
         const optionsArg = node.arguments[1];
         missingTimeout = !optionsArg || optionsArg.type !== TSESTree.AST_NODE_TYPES.ObjectExpression || !objectHasProperty(optionsArg, ['timeout', 'signal']);
    }
    // --- Check for request (deprecated) --- 
    else if (callee.type === TSESTree.AST_NODE_TYPES.Identifier && callee.name === 'request') {
        library = 'request';
        callDetail = 'request';
        const optionsArg = node.arguments[0];
        if (optionsArg && optionsArg.type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             missingTimeout = !objectHasProperty(optionsArg, ['timeout']);
        } else if (node.arguments.length > 1 && node.arguments[1]?.type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             missingTimeout = !objectHasProperty(node.arguments[1] as TSESTree.ObjectExpression, ['timeout']);
        } else {
             missingTimeout = true; 
        }
    } else if (callee.type === TSESTree.AST_NODE_TYPES.MemberExpression && 
               callee.object.type === TSESTree.AST_NODE_TYPES.Identifier && 
               callee.object.name === 'request' &&
               callee.property.type === TSESTree.AST_NODE_TYPES.Identifier) { 
         library = 'request';
         callDetail = `request.${callee.property.name}`;
         const optionsArg = node.arguments[0]; 
         if (optionsArg && optionsArg.type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             missingTimeout = !objectHasProperty(optionsArg, ['timeout']);
         } else if (node.arguments.length > 1 && node.arguments[1]?.type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             missingTimeout = !objectHasProperty(node.arguments[1] as TSESTree.ObjectExpression, ['timeout']);
         } else {
              missingTimeout = true;
         }
    }

    // Add finding logic...
    if (library !== 'unknown' && missingTimeout) {
        if (!findings.some(f => f.file === filePath && f.line === line && f.library === library && f.type === 'Potential Missing Timeout')) {
            findings.push({
                file: filePath,
                line: line,
                type: 'Potential Missing Timeout', 
                severity: 'Low', 
                library: library,
                message: `Potential missing timeout or cancellation signal in ${library} call.`,
                details: `Call found: ${callDetail} near line ${line}. Review configuration for timeouts or cancellation.`
            });
        }
    }
}

/**
 * Helper to check if an ObjectExpression node has specific property keys.
 */
function objectHasProperty(node: TSESTree.ObjectExpression | TSESTree.ObjectPattern | undefined, propertyNames: string[]): boolean {
    if (!node || node.type !== TSESTree.AST_NODE_TYPES.ObjectExpression) return false;
    return node.properties.some(prop => 
        prop.type === TSESTree.AST_NODE_TYPES.Property &&
        prop.key.type === TSESTree.AST_NODE_TYPES.Identifier &&
        propertyNames.includes(prop.key.name)
    );
}