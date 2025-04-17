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
];

const VIBESAFE_IGNORE_FILE = '.vibesafeignore';

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