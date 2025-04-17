#!/usr/bin/env node
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
// Load environment variables from .env file
require("dotenv/config");
const commander_1 = require("commander");
const secrets_1 = require("./scanners/secrets");
const dependencies_1 = require("./scanners/dependencies");
const fileTraversal_1 = require("./utils/fileTraversal");
const markdown_1 = require("./reporting/markdown");
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const chalk_1 = __importDefault(require("chalk"));
// Define a combined finding type if needed later
// Helper for coloring severities
function colorSeverity(severity) {
    switch (severity) {
        case 'Critical': return chalk_1.default.red.bold(severity);
        case 'High': return chalk_1.default.red(severity);
        case 'Medium': return chalk_1.default.yellow(severity);
        case 'Low': return chalk_1.default.blue(severity);
        case 'None': return chalk_1.default.gray(severity);
        default: return severity;
    }
}
const program = new commander_1.Command();
program
    .name('vibeshield')
    .description('A CLI tool to scan your codebase for security vibes.')
    .version('0.0.1');
program.command('scan')
    .description('Scan a directory for potential security issues.')
    .argument('[directory]', 'Directory to scan', '.')
    .option('-o, --output <file>', 'Specify JSON output file path (e.g., report.json)')
    .option('-r, --report <file>', 'Specify Markdown report file path (e.g., report.md)')
    .option('--high-only', 'Only report high severity issues')
    .action((directory, options) => __awaiter(void 0, void 0, void 0, function* () {
    const rootDir = path_1.default.resolve(directory);
    console.log(`Scanning directory: ${rootDir}`);
    if (options.highOnly) {
        console.log('(--high-only flag detected)');
    }
    if (options.output) {
        console.log(`Output will be written to: ${options.output}`);
    }
    if (options.report) {
        console.log(`Markdown report will be written to: ${options.report}`);
    }
    // --- Findings Aggregation ---
    let allSecretFindings = [];
    let allDependencyFindings = [];
    // --- Detect Package Manager (Phase 3.1) ---
    const detectedManagers = (0, dependencies_1.detectPackageManagers)(rootDir);
    console.log(`Detected package managers: ${detectedManagers.join(', ')}`);
    // --- Parse Dependencies (Phase 3.2) ---
    const dependencyInfoList = (0, dependencies_1.parseDependencies)(rootDir, detectedManagers);
    if (dependencyInfoList.length > 0) {
        console.log(`Parsed ${dependencyInfoList.length} dependencies.`);
    }
    // --- File Traversal (Phase 2.2) ---
    const filesToScan = (0, fileTraversal_1.getFilesToScan)(directory);
    // --- Secrets Scan (Phase 2.1 / 2.3) ---
    console.log(`Scanning ${filesToScan.length} files for secrets...`);
    filesToScan.forEach(filePath => {
        const findings = (0, secrets_1.scanFileForSecrets)(filePath);
        const relativeFindings = findings.map(f => (Object.assign(Object.assign({}, f), { file: path_1.default.relative(rootDir, f.file) })));
        allSecretFindings = allSecretFindings.concat(relativeFindings);
    });
    // --- Dependency CVE Lookup (Phase 3.3 & 3.4) ---
    if (dependencyInfoList.length > 0) {
        allDependencyFindings = yield (0, dependencies_1.lookupCves)(dependencyInfoList);
        const vulnCount = allDependencyFindings.reduce((count, dep) => count + dep.vulnerabilities.length, 0);
        const highOrCriticalVulnCount = allDependencyFindings.filter(dep => dep.maxSeverity === 'High' || dep.maxSeverity === 'Critical').length;
        console.log(`CVE lookup complete. Found ${vulnCount} vulnerabilities (${highOrCriticalVulnCount} High/Critical) across dependencies.`);
    }
    else {
        console.log('Skipping CVE lookup as no dependencies were parsed.');
    }
    // --- Filtering & Reporting (Phase 2.3 / 3.4) --- 
    const reportSecretFindings = options.highOnly
        ? allSecretFindings.filter(f => f.severity === 'High')
        : allSecretFindings;
    const reportDependencyFindings = options.highOnly
        ? allDependencyFindings.filter(dep => (dep.maxSeverity === 'High' || dep.maxSeverity === 'Critical') || dep.error)
        : allDependencyFindings.filter(dep => dep.vulnerabilities.length > 0 || dep.error);
    // --- Output Generation ---
    const reportData = { secretFindings: reportSecretFindings, dependencyFindings: reportDependencyFindings };
    // Generate JSON if requested
    if (options.output) {
        try {
            const outputJsonData = {
                secrets: reportSecretFindings,
                dependencies: reportDependencyFindings,
            };
            fs_1.default.writeFileSync(options.output, JSON.stringify(outputJsonData, null, 2));
            console.log(`JSON results successfully written to ${options.output}`);
        }
        catch (error) {
            console.error(`Error writing JSON output file ${options.output}:`, error);
            // Decide if this should be fatal? Maybe not if MD report is also requested.
        }
    }
    // Generate Markdown Report if requested
    if (options.report) {
        try {
            // Await the async report generation
            const markdownContent = yield (0, markdown_1.generateMarkdownReport)(reportData);
            fs_1.default.writeFileSync(options.report, markdownContent);
            console.log(`Markdown report successfully written to ${options.report}`);
        }
        catch (error) {
            console.error(`Error writing Markdown report file ${options.report}:`, error);
        }
    }
    // Print to console ONLY if neither JSON nor Markdown output was specified
    if (!options.output && !options.report) {
        // Print secrets to console
        if (reportSecretFindings.length > 0) {
            console.log(chalk_1.default.bold('\nPotential Secrets Found:'));
            reportSecretFindings.forEach(finding => {
                // Apply color to severity
                console.log(`  - [${colorSeverity(finding.severity)}] ${finding.type} in ${chalk_1.default.cyan(finding.file)}:${chalk_1.default.yellow(finding.line)}`);
            });
        }
        else {
            console.log('No potential secrets found in scanned files.');
        }
        // Print dependency findings to console
        if (reportDependencyFindings.length > 0) {
            console.log(chalk_1.default.bold('\nDependencies with Issues Found:'));
            reportDependencyFindings.sort((a, b) => severityToSortOrder(b.maxSeverity) - severityToSortOrder(a.maxSeverity));
            reportDependencyFindings.forEach(dep => {
                if (dep.error) {
                    console.log(`  - [${chalk_1.default.red.bold('ERROR')}] ${chalk_1.default.magenta(dep.name)}@${chalk_1.default.gray(dep.version)}: (${dep.error})`);
                }
                else if (dep.vulnerabilities.length > 0) {
                    const cveIds = dep.vulnerabilities.map(v => v.id).slice(0, 3).join(', ');
                    const moreCvEs = dep.vulnerabilities.length > 3 ? '...' : '';
                    // Apply color to severity and dependency name/version
                    console.log(`  - [${colorSeverity(dep.maxSeverity)}] ${chalk_1.default.magenta(dep.name)}@${chalk_1.default.gray(dep.version)}: ${dep.vulnerabilities.length} vulnerabilities (${chalk_1.default.dim(cveIds)}${moreCvEs})`);
                }
            });
        }
        else if (dependencyInfoList.length > 0 && !options.highOnly) {
            console.log('\nNo vulnerabilities found matching criteria in scanned dependencies.');
        }
    }
    console.log('\nScan complete.');
    // Exit code logic (Phase 1.2 / 3.4)
    const highSeveritySecrets = allSecretFindings.some(f => f.severity === 'High');
    const highSeverityDeps = allDependencyFindings.some(d => d.maxSeverity === 'High' || d.maxSeverity === 'Critical');
    if (options.highOnly && (highSeveritySecrets || highSeverityDeps)) {
        console.log('Exiting with code 1 due to High/Critical severity findings (--high-only specified).');
        process.exit(1);
    }
}));
// Helper for sorting console output
function severityToSortOrder(severity) {
    switch (severity) {
        case 'Critical': return 5;
        case 'High': return 4;
        case 'Medium': return 3;
        case 'Low': return 2;
        case 'None': return 1;
        default: return 0;
    }
}
program.parse(process.argv);
