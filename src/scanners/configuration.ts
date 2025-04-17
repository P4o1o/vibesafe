import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';
import { FindingSeverity } from './dependencies'; // Re-use severity type

export interface ConfigFinding {
    file: string;
    key: string; // The problematic key found (e.g., 'DEBUG')
    value: any; // The insecure value found (e.g., true)
    type: 'Insecure Setting' | 'Permissive CORS'; // Add more types as needed
    severity: FindingSeverity;
    message: string; // Description of the issue
}

interface CheckDefinition {
    keyPattern: RegExp; // Regex to match keys (e.g., /^DEBUG$/i)
    valuePattern: any; // Value to match (e.g., true, '*' for CORS)
    type: ConfigFinding['type'];
    severity: FindingSeverity;
    message: string;
}

// Define checks for common insecure settings
const INSECURE_CHECKS: CheckDefinition[] = [
    {
        keyPattern: /^(DEBUG|devMode)$/i, 
        valuePattern: true,
        type: 'Insecure Setting',
        severity: 'Medium',
        message: 'Debugging or development mode flag might be enabled.'
    },
    {
        // Simple check for permissive CORS origin (might need refinement for different structures)
        keyPattern: /^origin$/i, 
        valuePattern: '*',
        type: 'Permissive CORS',
        severity: 'High',
        message: `Permissive CORS policy found (allow all origins '*' detected).`
    },
    // Add more checks here (e.g., hardcoded default passwords?)
];

/**
 * Scans a parsed object for top-level insecure patterns.
 * TODO: Enhance to handle nested structures more robustly if needed.
 * @param data The object to scan.
 * @returns An array of ConfigFinding objects (without file path).
 */
function scanObjectForInsecurePatterns(data: any): Omit<ConfigFinding, 'file'>[] {
    const findings: Omit<ConfigFinding, 'file'>[] = [];
    // Keep track of keys found by specific checks to avoid duplication
    const specificallyFoundKeys: Set<string> = new Set(); 

    if (typeof data !== 'object' || data === null) {
        return findings;
    }

    for (const key in data) {
        if (Object.prototype.hasOwnProperty.call(data, key)) {
            const value = data[key];

            // --- Specific Structure Checks First --- 
            // Example: Basic check for CORS origin '*' in a nested object
            if (key.toLowerCase().includes('cors') && typeof value === 'object' && value !== null && value.origin === '*') {
                 const findingKey = `${key}.origin`;
                 findings.push({
                    key: findingKey,
                    value: value.origin,
                    type: 'Permissive CORS',
                    severity: 'High',
                    message: `Permissive CORS policy found (allow all origins '*' detected).`
                });
                specificallyFoundKeys.add(findingKey); // Mark this specific path as found
            }
            // TODO: Add other specific structure checks here

            // --- General Key/Value Pattern Checks --- 
            INSECURE_CHECKS.forEach(check => {
                 // Avoid re-flagging if a more specific check already found it (e.g. don't flag top-level 'origin' if 'cors.origin' was found)
                if (specificallyFoundKeys.has(key)) return;
                
                if (check.keyPattern.test(key) && value === check.valuePattern) {
                    findings.push({
                        key: key, 
                        value: value,
                        type: check.type,
                        severity: check.severity,
                        message: check.message
                    });
                }
            });
        }
    }
    return findings;
}

/**
 * Scans a configuration file (JSON or YAML) for insecure settings.
 * @param filePath Absolute path to the configuration file.
 * @returns An array of ConfigFinding objects.
 */
export function scanConfigFile(filePath: string): ConfigFinding[] {
    let findings: ConfigFinding[] = [];
    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        let parsedData: any;
        const ext = path.extname(filePath).toLowerCase();

        if (ext === '.json') { parsedData = JSON.parse(content); }
         else if (ext === '.yaml' || ext === '.yml') { parsedData = yaml.load(content); }
         else { return []; }

        if (typeof parsedData === 'object' && parsedData !== null) {
            // Use the simplified top-level scanner function
            const results = scanObjectForInsecurePatterns(parsedData);
            findings = results.map(finding => ({ ...finding, file: filePath }));
        }

    } catch (error: any) {
        console.warn(`Failed to parse or scan config file ${path.basename(filePath)}: ${error.message}`);
    }
    return findings;
} 