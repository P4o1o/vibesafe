"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getFilesToScan = getFilesToScan;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const ignore_1 = __importDefault(require("ignore"));
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
const VIBESHIELD_IGNORE_FILE = '.vibeshieldignore';
/**
 * Reads ignore patterns from .vibeshieldignore file if it exists.
 * @param rootDir The root directory of the project.
 * @returns An array of patterns from the file.
 */
function readVibeShieldIgnore(rootDir) {
    const ignoreFilePath = path_1.default.join(rootDir, VIBESHIELD_IGNORE_FILE);
    if (fs_1.default.existsSync(ignoreFilePath)) {
        try {
            return fs_1.default.readFileSync(ignoreFilePath, 'utf-8').split('\n').filter(line => line.trim() !== '' && !line.startsWith('#'));
        }
        catch (error) {
            console.warn(`Error reading ${VIBESHIELD_IGNORE_FILE}:`, error);
        }
    }
    return [];
}
/**
 * Recursively finds all files in a directory, respecting ignore patterns.
 * @param startDir The directory to start traversal from.
 * @param rootDir The root project directory (for locating .vibeshieldignore).
 * @param ig The ignore instance.
 * @returns An array of file paths relative to the rootDir.
 */
function findFilesRecursive(startDir, rootDir, ig) {
    let results = [];
    try {
        const entries = fs_1.default.readdirSync(startDir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path_1.default.join(startDir, entry.name);
            const relativePath = path_1.default.relative(rootDir, fullPath);
            // Check if the path should be ignored BEFORE recursing
            if (ig.ignores(relativePath)) {
                continue;
            }
            if (entry.isDirectory()) {
                results = results.concat(findFilesRecursive(fullPath, rootDir, ig));
            }
            else if (entry.isFile()) {
                // Optional: Add checks for file size or binary files here if needed
                results.push(fullPath);
            }
        }
    }
    catch (error) {
        if (error.code === 'EACCES') {
            console.warn(`Permission denied accessing directory: ${startDir}`);
        }
        else {
            console.error(`Error reading directory ${startDir}:`, error);
        }
    }
    return results;
}
/**
 * Gets a list of all files to scan in the project directory,
 * respecting default ignores and .vibeshieldignore.
 * @param rootDir The root directory to scan.
 * @returns An array of absolute file paths.
 */
function getFilesToScan(rootDir = '.') {
    const absoluteRootDir = path_1.default.resolve(rootDir);
    const ig = (0, ignore_1.default)();
    // Add default patterns
    ig.add(DEFAULT_IGNORE_PATTERNS);
    // Add patterns from .vibeshieldignore
    const customIgnorePatterns = readVibeShieldIgnore(absoluteRootDir);
    ig.add(customIgnorePatterns);
    console.log('Starting file traversal...');
    const files = findFilesRecursive(absoluteRootDir, absoluteRootDir, ig);
    console.log(`Traversal complete. Found ${files.length} files to scan.`);
    return files;
}
