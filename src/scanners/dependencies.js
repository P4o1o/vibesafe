"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectPackageManagers = detectPackageManagers;
exports.parseDependencies = parseDependencies;
exports.lookupCves = lookupCves;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const axios_1 = __importDefault(require("axios"));
const ora_1 = __importDefault(require("ora"));
const KNOWN_MANAGERS = [
    { name: 'npm', manifestFile: 'package.json', lockFile: 'package-lock.json' },
    { name: 'yarn', manifestFile: 'package.json', lockFile: 'yarn.lock' },
    { name: 'pnpm', manifestFile: 'package.json', lockFile: 'pnpm-lock.yaml' },
    { name: 'pip', manifestFile: 'requirements.txt' }, // Basic pip
    { name: 'poetry', manifestFile: 'pyproject.toml', lockFile: 'poetry.lock' }, // Poetry uses pyproject.toml
    { name: 'maven', manifestFile: 'pom.xml' },
    { name: 'gradle', manifestFile: 'build.gradle' }, // Or build.gradle.kts
    // TODO: Add more (Composer, Bundler, Cargo, Go Modules, etc.)
];
const OSV_BATCH_API_URL = 'https://api.osv.dev/v1/querybatch';
// Map our PackageManagers to OSV ecosystem names
const ECOSYSTEM_MAP = {
    npm: 'npm',
    yarn: 'npm', // OSV uses 'npm' for yarn as well
    pnpm: 'npm', // and pnpm
    pip: 'PyPI',
    poetry: 'PyPI',
    maven: 'Maven',
    gradle: 'Maven', // Often uses Maven repositories
    unknown: null,
};
// CVSS Score to Severity Mapping (example)
const CVSS_THRESHOLDS = [
    { level: 'Critical', minScore: 9.0 },
    { level: 'High', minScore: 7.0 },
    { level: 'Medium', minScore: 4.0 },
    { level: 'Low', minScore: 0.1 },
    { level: 'None', minScore: 0 },
];
/**
 * Extracts the highest CVSS v3 score from OSV severity info.
 * @param severities Array of OSV severity objects.
 * @returns The highest CVSS v3 score found, or 0 if none.
 */
function getHighestCvssScore(severities) {
    if (!severities)
        return 0;
    let maxScore = 0;
    for (const severity of severities) {
        // Prioritize CVSS V3, but might fall back to others if needed
        if (severity.type === 'CVSS_V3') {
            const score = parseFloat(severity.score);
            if (!isNaN(score)) {
                maxScore = Math.max(maxScore, score);
            }
        }
        // TODO: Add fallback logic for other types like CVSS_V2 if necessary
    }
    return maxScore;
}
/**
 * Determines the finding severity based on CVSS score.
 * @param score The CVSS score.
 * @returns The corresponding FindingSeverity.
 */
function scoreToSeverity(score) {
    for (const threshold of CVSS_THRESHOLDS) {
        if (score >= threshold.minScore) {
            return threshold.level;
        }
    }
    return 'None'; // Should not happen if thresholds cover 0
}
/**
 * Detects the package manager(s) used in a given directory by checking for specific files.
 * @param rootDir The root directory of the project to check.
 * @returns An array of detected PackageManager names.
 */
function detectPackageManagers(rootDir) {
    const detected = new Set();
    for (const manager of KNOWN_MANAGERS) {
        const manifestPath = path_1.default.join(rootDir, manager.manifestFile);
        const lockPath = manager.lockFile ? path_1.default.join(rootDir, manager.lockFile) : null;
        // Check if either manifest or lock file exists
        // Prioritize lock file detection if available
        if (lockPath && fs_1.default.existsSync(lockPath)) {
            detected.add(manager.name);
        }
        else if (fs_1.default.existsSync(manifestPath)) {
            // Special handling for generic files like package.json or pyproject.toml
            if (manager.name === 'npm' || manager.name === 'yarn' || manager.name === 'pnpm') {
                // If package.json exists but no specific lock file, we can't be sure
                // Only add if no other node manager was detected via lock file
                if (!detected.has('npm') && !detected.has('yarn') && !detected.has('pnpm')) {
                    // Could tentatively add 'npm' or maybe 'node' generic? Let's skip for now to avoid ambiguity without lockfile.
                }
            }
            else if (manager.name === 'poetry') {
                // Check pyproject.toml specifically for [tool.poetry] section if needed for more accuracy
                // For now, just existence is enough
                detected.add(manager.name);
            }
            else {
                detected.add(manager.name); // Add for other manifests like requirements.txt, pom.xml
            }
        }
    }
    // Handle gradle kts variant
    if (!detected.has('gradle') && fs_1.default.existsSync(path_1.default.join(rootDir, 'build.gradle.kts'))) {
        detected.add('gradle');
    }
    const result = Array.from(detected);
    return result.length > 0 ? result : ['unknown'];
}
// TODO: Implement Phase 3.2: Parse dependencies
// TODO: Implement Phase 3.3: CVE lookup
// TODO: Implement Phase 3.4: Threshold filtering 
/**
 * Parses dependencies from a package.json file.
 * @param rootDir The root directory containing package.json.
 * @returns An array of DependencyInfo objects.
 */
function parsePackageJson(rootDir) {
    const filePath = path_1.default.join(rootDir, 'package.json');
    const dependencies = [];
    if (!fs_1.default.existsSync(filePath)) {
        console.warn('package.json not found, cannot parse Node dependencies.');
        return dependencies;
    }
    try {
        const packageJsonContent = fs_1.default.readFileSync(filePath, 'utf-8');
        const packageJson = JSON.parse(packageJsonContent);
        const extractDeps = (depSection, manager = 'npm') => {
            if (!depSection)
                return;
            for (const name in depSection) {
                dependencies.push({
                    name: name,
                    version: depSection[name],
                    packageManager: manager, // Assume npm/yarn/pnpm - could refine later if needed
                    sourceFile: 'package.json'
                });
            }
        };
        extractDeps(packageJson.dependencies);
        extractDeps(packageJson.devDependencies);
        extractDeps(packageJson.peerDependencies); // Optional: include peerDependencies?
        // Optional: include optionalDependencies?
    }
    catch (error) {
        console.error(`Error parsing ${filePath}:`, error);
    }
    return dependencies;
}
/**
 * Parses dependencies based on detected package managers.
 * @param rootDir The root directory.
 * @param managers Array of detected package managers.
 * @returns An array of DependencyInfo objects from all detected managers.
 */
function parseDependencies(rootDir, managers) {
    let allDependencies = [];
    // Use a Set to avoid duplicate parsing if multiple node managers are detected (though detection logic tries to avoid this)
    const processedManagers = new Set();
    for (const manager of managers) {
        if ((manager === 'npm' || manager === 'yarn' || manager === 'pnpm') && !processedManagers.has('node')) {
            console.log(`Parsing dependencies from package.json for ${manager}...`);
            allDependencies = allDependencies.concat(parsePackageJson(rootDir));
            processedManagers.add('node'); // Mark node deps as processed
        }
        else if (manager === 'pip') {
            // TODO: Implement requirements.txt parsing
            console.log('Parsing requirements.txt not yet implemented.');
        }
        else if (manager === 'poetry') {
            // TODO: Implement pyproject.toml parsing
            console.log('Parsing pyproject.toml not yet implemented.');
        }
        // Add other parsers here
    }
    return allDependencies;
}
// TODO: Implement Phase 3.3: CVE lookup
// TODO: Implement Phase 3.4: Threshold filtering 
/**
 * Looks up vulnerabilities and calculates max severity for dependencies.
 * @param dependencies Array of DependencyInfo objects.
 * @returns Array of DependencyFinding objects.
 */
function lookupCves(dependencies) {
    return __awaiter(this, void 0, void 0, function* () {
        const initialFindings = dependencies.map(dep => (Object.assign(Object.assign({}, dep), { vulnerabilities: [], maxSeverity: 'None', error: ECOSYSTEM_MAP[dep.packageManager] ? undefined : 'Unsupported package manager for CVE lookup' })));
        const queries = [];
        const queryIndexToFindingIndex = []; // Map query index back to initialFindings index
        // Prepare queries for OSV API
        initialFindings.forEach((finding, index) => {
            const ecosystem = ECOSYSTEM_MAP[finding.packageManager];
            if (ecosystem && finding.version && !finding.error) {
                queries.push({
                    package: { name: finding.name, ecosystem: ecosystem },
                    version: finding.version,
                });
                queryIndexToFindingIndex.push(index); // Store the original index
            }
        });
        if (queries.length === 0) {
            console.log('No dependencies suitable for CVE lookup.');
            return initialFindings;
        }
        const spinner = (0, ora_1.default)(`Querying OSV.dev for ${queries.length} dependencies...`).start();
        try {
            const response = yield axios_1.default.post(OSV_BATCH_API_URL, { queries });
            if (response.status !== 200 || !response.data || !response.data.results) {
                spinner.fail('OSV API request failed (Invalid Response).');
                throw new Error(`OSV API request failed with status ${response.status}`);
            }
            // Map results back to findings
            response.data.results.forEach((result, queryIdx) => {
                const findingIndex = queryIndexToFindingIndex[queryIdx];
                const targetFinding = initialFindings[findingIndex];
                if (targetFinding) {
                    if (result && result.vulns && result.vulns.length > 0) {
                        targetFinding.vulnerabilities = result.vulns;
                        // Calculate max severity for this dependency
                        let maxCvss = 0;
                        for (const vuln of result.vulns) {
                            maxCvss = Math.max(maxCvss, getHighestCvssScore(vuln.severity));
                        }
                        targetFinding.maxSeverity = scoreToSeverity(maxCvss);
                    }
                    else {
                        targetFinding.maxSeverity = 'None'; // Explicitly set to None if no vulns found
                    }
                }
                else {
                    console.warn(`Could not map OSV result back for query index ${queryIdx}`);
                }
            });
            spinner.succeed('OSV CVE lookup complete.');
        }
        catch (error) {
            spinner.fail(`OSV API request failed: ${error.message}`);
            // Mark queried dependencies as having an error
            queryIndexToFindingIndex.forEach(findingIndex => {
                if (initialFindings[findingIndex] && !initialFindings[findingIndex].error) {
                    initialFindings[findingIndex].error = 'CVE lookup failed';
                    initialFindings[findingIndex].maxSeverity = 'None'; // Or maybe 'Unknown'?
                }
            });
        }
        return initialFindings;
    });
}
// TODO: Implement Phase 3.4: Threshold filtering 
