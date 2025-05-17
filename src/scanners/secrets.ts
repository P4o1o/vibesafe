import fs from 'fs';
import path from 'path';
// Import the shared severity type
import { FindingSeverity } from './dependencies';

// Define types for findings
export interface SecretFinding {
  file: string;
  line: number;
  type: string; // e.g., 'AWS Key', 'Generic API Key', 'High Entropy String'
  value: string; // The matched secret or high-entropy string
  // Use the shared severity type, allowing 'Info'
  severity: FindingSeverity | 'Low' | 'Medium' | 'High';
}

// --- Entropy Calculation ---

/**
 * Calculates the Shannon entropy of a string.
 * @param str The input string.
 * @returns The Shannon entropy value (in bits per character).
 */
function calculateShannonEntropy(str: string): number {
  if (!str) {
    return 0;
  }
  const charCounts: { [key: string]: number } = {};
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
const ENTROPY_CANDIDATE_REGEX = /[a-zA-Z0-9\/\+=]{20,}/g; // Note: Double backslash for literal \ before / and += for regex

// List of common binary file extensions to skip
const BINARY_FILE_EXTENSIONS = new Set([
  // Images
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico',
  // Fonts
  '.otf', '.ttf', '.woff', '.woff2', '.eot',
  // Archives
  '.zip', '.tar', '.gz', '.rar', '.7z',
  // Documents
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  // Executables & Libraries
  '.exe', '.dll', '.so', '.dylib', '.app', '.msi',
  // Media
  '.mp3', '.wav', '.ogg', '.mp4', '.mov', '.avi', '.wmv', '.mkv', '.flv',
  // Other
  '.class', '.jar', '.pyc', '.pyo', '.o', '.a', '.lib', '.obj', '.swp', '.DS_Store', 'Thumbs.db'
]);

// --- Regex Patterns ---

// Define basic regex patterns (can be expanded)
const secretPatterns = [
  // Keep original severity for general cases
  { type: 'AWS Access Key ID', pattern: /(?:AKIA|ASIA)[A-Z2-7]{16}/g, severity: 'High' as const },
  { type: 'AWS Secret Access Key', pattern: /(?<![A-Za-z0-9\/+=])[A-Za-z0-9\/+=]{40}(?![A-Za-z0-9\/+=])/g, severity: 'High' as const },
  { type: 'Generic API Key', pattern: /[aA][pP][iI]_?[kK][eE][yY]\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{16,}['"]?/g, severity: 'Medium' as const },
  // Add more patterns: JWT, SSH keys, etc.
];

/**
 * Scans a single file for secrets based on regex patterns and entropy analysis.
 * Special handling for .env files to downgrade severity to Info.
 * @param filePath The path to the file to scan.
 * @returns An array of SecretFinding objects.
 */
export function scanFileForSecrets(filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];

  // Skip binary files
  const fileExtension = path.extname(filePath).toLowerCase();
  if (BINARY_FILE_EXTENSIONS.has(fileExtension)) {
    return findings; // Skip scanning for binary files
  }

  // Check if the file is likely an environment file
  const isEnvFile = /\.env($|\.)/.test(path.basename(filePath));

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    lines.forEach((lineContent, index) => {
      const lineNumber = index + 1;

      // 1. Check specific regex patterns
      secretPatterns.forEach(({ type, pattern, severity }) => {
        let match;
        pattern.lastIndex = 0; // Reset lastIndex for global regex
        while ((match = pattern.exec(lineContent)) !== null) {
          const matchedValue = match[0];

          // Heuristic for AWS Secret Access Key: check character uniqueness
          if (type === 'AWS Secret Access Key') {
            const uniqueChars = new Set(matchedValue.split('')).size;
            // If fewer than, say, 15 unique characters in a 40-char string,
            // it's less likely to be a real, complex key.
            if (uniqueChars < 15) {
              continue; // Skip this likely false positive
            }
          }

          findings.push({
            file: filePath,
            line: lineNumber,
            // Adjust type if found in .env file
            type: isEnvFile ? 'Local Environment Secret' : type,
            value: matchedValue,
            // Downgrade severity to Info if found in .env file
            severity: isEnvFile ? 'Info' : severity,
          });
        }
      });

      // 2. Check for high entropy strings
      // Don't check entropy in .env files by default, as they often contain base64 etc.
      if (!isEnvFile) {
        let entropyMatch;
        ENTROPY_CANDIDATE_REGEX.lastIndex = 0; // Reset lastIndex for global regex
        while ((entropyMatch = ENTROPY_CANDIDATE_REGEX.exec(lineContent)) !== null) {
          const candidate = entropyMatch[0];
          // Avoid re-flagging things already caught by specific patterns
          const alreadyFound = findings.some(f => f.line === lineNumber && f.value === candidate);
          if (alreadyFound) continue;

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
      }
    });
  } catch (error: any) {
    // Handle potential errors like permission issues
    if (error.code === 'ENOENT') {
       console.warn(`File not found: ${filePath}`);
    } else if (error.code === 'EACCES') {
        console.warn(`Permission denied: ${filePath}`);
    } else {
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
function checkEntropy(value: string): boolean {
  // Placeholder for Shannon entropy calculation
  return false;
}

// TODO: Implement file traversal logic (Phase 2.2)
// TODO: Implement scoring refinement (Phase 2.3) 