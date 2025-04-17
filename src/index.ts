#!/usr/bin/env node

// Load environment variables from .env file
import 'dotenv/config';

import { Command } from 'commander';
import { scanFileForSecrets, SecretFinding } from './scanners/secrets';
import { detectPackageManagers, parseDependencies, lookupCves, DependencyInfo, DependencyFinding, FindingSeverity } from './scanners/dependencies';
import { getFilesToScan } from './utils/fileTraversal';
import { generateMarkdownReport } from './reporting/markdown';
import path from 'path';
import fs from 'fs';
import chalk from 'chalk';

// Define a combined finding type if needed later

// Helper for coloring severities
function colorSeverity(severity: FindingSeverity | SecretFinding['severity']): string {
    switch (severity) {
        case 'Critical': return chalk.red.bold(severity);
        case 'High': return chalk.red(severity);
        case 'Medium': return chalk.yellow(severity);
        case 'Low': return chalk.blue(severity);
        case 'None': return chalk.gray(severity);
        default: return severity;
    }
}

const program = new Command();

program
  .name('vibesafe')
  .description('A CLI tool to scan your codebase for security vibes.')
  .version('0.0.1');

program.command('scan')
  .description('Scan a directory for potential security issues.')
  .argument('[directory]', 'Directory to scan', '.')
  .option('-o, --output <file>', 'Specify JSON output file path (e.g., report.json)')
  .option('-r, --report <file>', 'Specify Markdown report file path (e.g., report.md)')
  .option('--high-only', 'Only report high severity issues')
  .action(async (directory, options) => {
    const rootDir = path.resolve(directory);
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
    let allSecretFindings: SecretFinding[] = [];
    let allDependencyFindings: DependencyFinding[] = [];

    // --- File Traversal (Phase 2.2) ---
    const filesToScan = getFilesToScan(directory);

    // --- Detect Package Manager (Phase 3.1) ---
    const detectedManagers = detectPackageManagers(filesToScan, rootDir);
    // Use Object.keys() to get the names from the map for logging
    const managerNames = Object.keys(detectedManagers);
    console.log(`Detected package managers: ${managerNames.length > 0 ? managerNames.join(', ') : 'none'}`);

    // --- Parse Dependencies (Phase 3.2) ---
    const dependencyInfoList = parseDependencies(detectedManagers);
    if (dependencyInfoList.length > 0) {
        console.log(`Parsed ${dependencyInfoList.length} dependencies.`);
    }

    // --- Secrets Scan (Phase 2.1 / 2.3) ---
    console.log(`Scanning ${filesToScan.length} files for secrets...`);
    filesToScan.forEach(filePath => {
        const findings = scanFileForSecrets(filePath);
        const relativeFindings = findings.map(f => ({ ...f, file: path.relative(rootDir, f.file) }));
        allSecretFindings = allSecretFindings.concat(relativeFindings);
    });

    // --- Dependency CVE Lookup (Phase 3.3 & 3.4) ---
    if (dependencyInfoList.length > 0) {
        allDependencyFindings = await lookupCves(dependencyInfoList);
        const vulnCount = allDependencyFindings.reduce((count, dep) => count + dep.vulnerabilities.length, 0);
        const highOrCriticalVulnCount = allDependencyFindings.filter(dep => dep.maxSeverity === 'High' || dep.maxSeverity === 'Critical').length;
        console.log(`CVE lookup complete. Found ${vulnCount} vulnerabilities (${highOrCriticalVulnCount} High/Critical) across dependencies.`);
    } else {
        console.log('Skipping CVE lookup as no dependencies were parsed.');
    }

    // Separate Info findings
    const infoSecretFindings = allSecretFindings.filter(f => f.severity === 'Info');
    const standardSecretFindings = allSecretFindings.filter(f => f.severity !== 'Info');

    // --- Filtering & Reporting (Phase 2.3 / 3.4) --- 
    const reportSecretFindings = options.highOnly
      ? standardSecretFindings.filter(f => f.severity === 'High') 
      : standardSecretFindings;
    
    const reportDependencyFindings = options.highOnly
      ? allDependencyFindings.filter(dep => (dep.maxSeverity === 'High' || dep.maxSeverity === 'Critical')) // Exclude errors when highOnly
      : allDependencyFindings.filter(dep => dep.vulnerabilities.length > 0 || dep.error);

    // --- Output Generation ---
    const reportData = { 
        secretFindings: reportSecretFindings, // Report only standard secrets
        dependencyFindings: reportDependencyFindings 
    };

    // Generate JSON if requested
    if (options.output) {
        try {
            const outputJsonData = {
                secrets: reportSecretFindings,
                dependencies: reportDependencyFindings,
            }
            fs.writeFileSync(options.output, JSON.stringify(outputJsonData, null, 2));
            console.log(`JSON results successfully written to ${options.output}`);
        } catch (error) {
            console.error(`Error writing JSON output file ${options.output}:`, error);
            // Decide if this should be fatal? Maybe not if MD report is also requested.
        }
    }

    // Generate Markdown Report if requested
    if (options.report) {
        try {
            // Await the async report generation
            const markdownContent = await generateMarkdownReport(reportData); 
            fs.writeFileSync(options.report, markdownContent);
            console.log(`Markdown report successfully written to ${options.report}`);
        } catch (error) {
             console.error(`Error writing Markdown report file ${options.report}:`, error);
        }
    }

    // Print to console ONLY if neither JSON nor Markdown output was specified
    if (!options.output && !options.report) {
        // Handle Info findings first
        if (infoSecretFindings.length > 0) {
            console.log(chalk.blue.bold('\nInfo:'));
            // Get unique .env files found
            const envFiles = [...new Set(infoSecretFindings.map(f => f.file))];
            envFiles.forEach(file => {
                console.log(`  - Found potential secrets in ${chalk.cyan(file)}. Ensure this file is in .gitignore and not committed to version control.`);
            });
        }

        // Print standard secrets to console
        if (reportSecretFindings.length > 0) {
            console.log(chalk.bold('\nPotential Secrets Found:'));
            reportSecretFindings.forEach(finding => {
                console.log(`  - [${colorSeverity(finding.severity)}] ${finding.type} in ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`);
            });
        } else if (allSecretFindings.length === 0) {
            // Only print "no secrets" if no standard *or* info secrets were found
            console.log('No potential secrets found in scanned files.');
        }

        // Print dependency findings to console
        if (reportDependencyFindings.length > 0) {
            console.log(chalk.bold('\nDependencies with Issues Found:'));
            reportDependencyFindings.sort((a, b) => severityToSortOrder(b.maxSeverity) - severityToSortOrder(a.maxSeverity));

            reportDependencyFindings.forEach(dep => {
                if (dep.error) {
                    console.log(`  - [${chalk.red.bold('ERROR')}] ${chalk.magenta(dep.name)}@${chalk.gray(dep.version)}: (${dep.error})`);
                } else if (dep.vulnerabilities.length > 0) {
                    const cveIds = dep.vulnerabilities.map(v => v.id).slice(0,3).join(', ');
                    const moreCvEs = dep.vulnerabilities.length > 3 ? '...' : '';
                    // Apply color to severity and dependency name/version
                    console.log(`  - [${colorSeverity(dep.maxSeverity)}] ${chalk.magenta(dep.name)}@${chalk.gray(dep.version)}: ${dep.vulnerabilities.length} vulnerabilities (${chalk.dim(cveIds)}${moreCvEs})`);
                }
            });
        } else if (dependencyInfoList.length > 0 && !options.highOnly) {
             console.log('\nNo vulnerabilities found matching criteria in scanned dependencies.');
        }
    }

    console.log('\nScan complete.');

    // Exit code logic (Phase 1.2 / 3.4)
    // Info findings should NOT affect exit code
    const highSeveritySecrets = reportSecretFindings.some(f => f.severity === 'High');
    const highSeverityDeps = reportDependencyFindings.some(d => d.maxSeverity === 'High' || d.maxSeverity === 'Critical');

    if (options.highOnly && (highSeveritySecrets || highSeverityDeps)) {
        console.log('Exiting with code 1 due to High/Critical severity findings (--high-only specified).');
        process.exit(1);
    }
  });

// Helper for sorting console output - Add Info level
function severityToSortOrder(severity: FindingSeverity | SecretFinding['severity']): number {
    switch (severity) {
        case 'Critical': return 5;
        case 'High': return 4;
        case 'Medium': return 3;
        case 'Low': return 2;
        case 'Info': return 1; // Info is below Low
        case 'None': return 0;
        default: return 0;
    }
}

program.parse(process.argv); 