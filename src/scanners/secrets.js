"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanFileForSecrets = scanFileForSecrets;
const fs_1 = __importDefault(require("fs"));
// --- Entropy Calculation ---
/**
 * Calculates the Shannon entropy of a string.
 * @param str The input string.
 * @returns The Shannon entropy value (in bits per character).
 */
function calculateShannonEntropy(str) {
    if (!str) {
        return 0;
    }
    const charCounts = {};
    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        charCounts[char] = (charCounts[char] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const char in charCounts) {
        const probability = charCounts[char] / len;
        entropy -= probability * Math.log2(probability);
    }
    return entropy;
}
// Configuration for entropy scanning
const MIN_ENTROPY_THRESHOLD = 4.0; // Threshold for considering a string high entropy (adjust as needed)
const MIN_STRING_LENGTH_FOR_ENTROPY = 20; // Minimum length of a string to check entropy
// Regex to find potential candidates for entropy check (e.g., alphanumeric strings > min length)
// This avoids checking entropy on every single word.
const ENTROPY_CANDIDATE_REGEX = /[a-zA-Z0-9\/\+=]{20,}/g;
// --- Regex Patterns ---
// Define basic regex patterns (can be expanded)
const secretPatterns = [
    { type: 'AWS Access Key ID', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'High' },
    { type: 'AWS Secret Access Key', pattern: /(?<![A-Za-z0-9\/+=])[A-Za-z0-9\/+=]{40}(?![A-Za-z0-9\/+=])/g, severity: 'High' },
    { type: 'Generic API Key', pattern: /[aA][pP][iI]_?[kK][eE][yY]\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{16,}['"]?/g, severity: 'Medium' },
    // Add more patterns: JWT, SSH keys, etc.
];
/**
 * Scans a single file for secrets based on regex patterns and entropy analysis.
 * @param filePath The path to the file to scan.
 * @returns An array of SecretFinding objects.
 */
function scanFileForSecrets(filePath) {
    const findings = [];
    try {
        const content = fs_1.default.readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');
        lines.forEach((lineContent, index) => {
            const lineNumber = index + 1;
            // 1. Check specific regex patterns
            secretPatterns.forEach(({ type, pattern, severity }) => {
                let match;
                pattern.lastIndex = 0; // Reset lastIndex for global regex
                while ((match = pattern.exec(lineContent)) !== null) {
                    findings.push({
                        file: filePath,
                        line: lineNumber,
                        type: type,
                        value: match[0],
                        severity: severity,
                    });
                }
            });
            // 2. Check for high entropy strings
            let entropyMatch;
            ENTROPY_CANDIDATE_REGEX.lastIndex = 0; // Reset lastIndex for global regex
            while ((entropyMatch = ENTROPY_CANDIDATE_REGEX.exec(lineContent)) !== null) {
                const candidate = entropyMatch[0];
                // Avoid re-flagging things already caught by specific patterns
                const alreadyFound = findings.some(f => f.line === lineNumber && f.value === candidate);
                if (alreadyFound)
                    continue;
                if (candidate.length >= MIN_STRING_LENGTH_FOR_ENTROPY) {
                    const entropy = calculateShannonEntropy(candidate);
                    if (entropy >= MIN_ENTROPY_THRESHOLD) {
                        findings.push({
                            file: filePath,
                            line: lineNumber,
                            type: 'High Entropy String',
                            value: candidate,
                            severity: 'Low', // Entropy findings often need review, start at Low
                        });
                    }
                }
            }
        });
    }
    catch (error) {
        // Handle potential errors like permission issues
        if (error.code === 'ENOENT') {
            console.warn(`File not found: ${filePath}`);
        }
        else if (error.code === 'EACCES') {
            console.warn(`Permission denied: ${filePath}`);
        }
        else {
            console.error(`Error reading file ${filePath}:`, error);
        }
    }
    return findings;
}
/**
 * TODO: Implement entropy checking logic.
 * This could analyze strings that don't match specific regex patterns
 * but have high randomness typical of keys/tokens.
 */
function checkEntropy(value) {
    // Placeholder for Shannon entropy calculation
    return false;
}
// TODO: Implement file traversal logic (Phase 2.2)
// TODO: Implement scoring refinement (Phase 2.3) 
