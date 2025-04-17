import fs from 'fs';
import path from 'path';
import ignore, { Ignore } from 'ignore';

const DEFAULT_IGNORE_PATTERNS = [
  'node_modules',
  'dist',
  'build',
  '.git',
  '.svn',
  '.hg',
  '*.log',
  '*.lock',
  '*.swp',
  '.DS_Store',
  'Thumbs.db',
  // Add other common ignores if needed
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'tsconfig.json',
  'README.md',
];

const VIBESAFE_IGNORE_FILE = '.vibesafeignore';

// --- .gitignore Check --- 

// Patterns we want to ensure are typically ignored by users
const SENSITIVE_PATTERNS_TO_CHECK = [
    '.env',
    '.env.*',       // Catch .env.local, .env.development etc.
    '*.env',       // Catch other potential env files
    // Add other common sensitive file patterns here if needed later
    // e.g., '*.pem', '*.key'?
];

export interface GitignoreWarning {
    type: 'MISSING' | 'PATTERN_NOT_IGNORED';
    message: string;
    pattern?: string; // The pattern that wasn't ignored
}

/**
 * Checks if .gitignore exists and if it ignores common sensitive patterns.
 * @param rootDir The root directory of the project.
 * @returns An array of warning objects.
 */
export function checkGitignoreStatus(rootDir: string): GitignoreWarning[] {
    const warnings: GitignoreWarning[] = [];
    const gitignorePath = path.join(rootDir, '.gitignore');

    if (!fs.existsSync(gitignorePath)) {
        warnings.push({
            type: 'MISSING',
            message: '.gitignore file not found. Recommend creating one and adding sensitive files (like .env*, *.log) to prevent accidental commits.'
        });
        return warnings; // No point checking patterns if the file doesn't exist
    }

    try {
        const gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');
        const ig = ignore().add(gitignoreContent);

        SENSITIVE_PATTERNS_TO_CHECK.forEach(pattern => {
            // Use a common example filename that matches the pattern
            // Note: This check isn't perfect, complex patterns could behave differently,
            // but it covers common cases like direct filenames or *.ext.
            const testFileName = pattern.includes('*') ? pattern.replace('*.', 'example.') : pattern;
            
            if (!ig.ignores(testFileName)) {
                warnings.push({
                    type: 'PATTERN_NOT_IGNORED',
                    message: `Pattern "${pattern}" is not covered by .gitignore. Consider adding it to prevent committing sensitive files.`, 
                    pattern: pattern
                });
            }
        });

    } catch (error: any) {
        console.warn(`Error reading or parsing .gitignore: ${error.message}`);
        // Don't block the scan, just warn about the check failure
    }

    return warnings;
}

/**
 * Reads ignore patterns from .vibesafeignore file if it exists.
 * @param rootDir The root directory of the project.
 * @returns An array of patterns from the file.
 */
function readVibeSafeIgnore(rootDir: string): string[] {
  const ignoreFilePath = path.join(rootDir, VIBESAFE_IGNORE_FILE);
  if (fs.existsSync(ignoreFilePath)) {
    try {
      return fs.readFileSync(ignoreFilePath, 'utf-8').split('\n').filter(line => line.trim() !== '' && !line.startsWith('#'));
    } catch (error) {
      console.warn(`Error reading ${VIBESAFE_IGNORE_FILE}:`, error);
    }
  }
  return [];
}

/**
 * Recursively finds all files in a directory, respecting ignore patterns.
 * @param startDir The directory to start traversal from.
 * @param rootDir The root project directory (for locating .vibesafeignore).
 * @param ig The ignore instance.
 * @returns An array of file paths relative to the rootDir.
 */
function findFilesRecursive(startDir: string, rootDir: string, ig: Ignore): string[] {
  let results: string[] = [];
  try {
    const entries = fs.readdirSync(startDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(startDir, entry.name);
      const relativePath = path.relative(rootDir, fullPath);

      // Check if the path should be ignored BEFORE recursing
      if (ig.ignores(relativePath)) {
        continue;
      }

      if (entry.isDirectory()) {
        results = results.concat(findFilesRecursive(fullPath, rootDir, ig));
      } else if (entry.isFile()) {
        // Optional: Add checks for file size or binary files here if needed
        results.push(fullPath);
      }
    }
  } catch (error: any) {
     if (error.code === 'EACCES') {
        console.warn(`Permission denied accessing directory: ${startDir}`);
     } else {
        console.error(`Error reading directory ${startDir}:`, error);
     }
  }
  return results;
}

/**
 * Gets a list of all files to scan in the project directory,
 * respecting default ignores and .vibesafeignore.
 * @param rootDir The root directory to scan.
 * @returns An array of absolute file paths.
 */
export function getFilesToScan(rootDir: string = '.'): string[] {
  const absoluteRootDir = path.resolve(rootDir);
  const ig = ignore();

  // Add default patterns
  ig.add(DEFAULT_IGNORE_PATTERNS);

  // Add patterns from .vibesafeignore
  const customIgnorePatterns = readVibeSafeIgnore(absoluteRootDir);
  ig.add(customIgnorePatterns);

  console.log('Starting file traversal...');
  const files = findFilesRecursive(absoluteRootDir, absoluteRootDir, ig);
  console.log(`Traversal complete. Found ${files.length} files to scan.`);
  return files;
} 