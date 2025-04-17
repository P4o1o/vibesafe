#!/usr/bin/env node

// Load environment variables from .env file
import 'dotenv/config';

import { Command } from 'commander';
import { scanFileForSecrets, SecretFinding } from './scanners/secrets';
import { detectPackageManagers, parseDependencies, lookupCves, DependencyInfo, DependencyFinding, FindingSeverity } from './scanners/dependencies';
import { getFilesToScan, checkGitignoreStatus, GitignoreWarning } from './utils/fileTraversal';
import { generateMarkdownReport } from './reporting/markdown';
import path from 'path';
import fs from 'fs';
import chalk from 'chalk';
import { scanConfigFile, ConfigFinding } from './scanners/configuration';
import { scanForUnvalidatedUploads, UploadFinding } from './scanners/uploads';
import { scanForExposedEndpoints, EndpointFinding } from './scanners/endpoints';

// Define a combined finding type if needed later

// Helper for coloring severities
function colorSeverity(severity: FindingSeverity | SecretFinding['severity'] | UploadFinding['severity']): string {
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
  .option('-r, --report [file]', 'Specify Markdown report file path (defaults to VIBESAFE-REPORT.md)')
  .option('--high-only', 'Only report high severity issues')
  .action(async (directory, options) => {
    const rootDir = path.resolve(directory);
    console.log(`Scanning directory: ${rootDir}`);
    if (options.highOnly) {
      console.log('(--high-only flag detected)');
    }
    if (options.output) {
      console.log(`JSON output will be written to: ${options.output}`);
    }
    
    // Determine report path based on options
    let reportPath: string | null = null;
    if (options.report) { // Check if -r or --report was used
        if (typeof options.report === 'string') {
            // User provided a specific filename
            reportPath = path.resolve(options.report);
            console.log(`Markdown report will be written to: ${reportPath}`);
        } else {
            // User used the flag without a filename, use default
            reportPath = path.join(rootDir, 'VIBESAFE-REPORT.md');
            console.log(`Markdown report will be written to default location: ${reportPath}`);
        }
    }

    // --- Moved: Check .gitignore Status --- 
    // We will call checkGitignoreStatus later, just declare the variable here
    let gitignoreWarnings: GitignoreWarning[] = [];

    // --- Findings Aggregation ---
    let allSecretFindings: SecretFinding[] = [];
    let allDependencyFindings: DependencyFinding[] = [];
    let allConfigFindings: ConfigFinding[] = [];
    let allUploadFindings: UploadFinding[] = [];
    let allEndpointFindings: EndpointFinding[] = [];

    // --- File Traversal (Phase 2.2) ---
    const filesToScan = getFilesToScan(directory);
    const configFilesToScan = filesToScan.filter(f => /\.(json|ya?ml)$/i.test(f));

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

    // --- Configuration Scan (Phase 6.1) ---
    console.log(`Scanning ${configFilesToScan.length} potential config files...`);
    configFilesToScan.forEach(filePath => {
        const findings = scanConfigFile(filePath);
        const relativeFindings = findings.map(f => ({ ...f, file: path.relative(rootDir, f.file) }));
        allConfigFindings = allConfigFindings.concat(relativeFindings);
    });

    // --- Upload Scan (Phase 6.2) ---
    // Define file extensions relevant for upload checks
    const UPLOAD_SCAN_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.vue', '.html']);
    const filesForUploadScan = filesToScan.filter(f => UPLOAD_SCAN_EXTENSIONS.has(path.extname(f).toLowerCase()));
    console.log(`Scanning ${filesForUploadScan.length} files for potential upload issues...`);
    filesForUploadScan.forEach(filePath => {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const findings = scanForUnvalidatedUploads(filePath, content);
            const relativeFindings = findings.map(f => ({ ...f, file: path.relative(rootDir, f.file) }));
            allUploadFindings = allUploadFindings.concat(relativeFindings);
        } catch (error: any) {
            // Avoid crashing if a single file fails (e.g., read permission)
            console.warn(chalk.yellow(`Could not scan ${path.relative(rootDir, filePath)} for uploads: ${error.message}`));
        }
    });

    // --- Endpoint Scan (Phase 6.3) ---
    // Define file extensions relevant for endpoint checks (JS/TS files)
    const ENDPOINT_SCAN_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx']);
    const filesForEndpointScan = filesToScan.filter(f => ENDPOINT_SCAN_EXTENSIONS.has(path.extname(f).toLowerCase()));
    console.log(`Scanning ${filesForEndpointScan.length} files for potentially exposed endpoints...`);
    filesForEndpointScan.forEach(filePath => {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const findings = scanForExposedEndpoints(filePath, content);
            const relativeFindings = findings.map(f => ({ ...f, file: path.relative(rootDir, f.file) }));
            allEndpointFindings = allEndpointFindings.concat(relativeFindings);
        } catch (error: any) {
            // Avoid crashing if a single file fails (e.g., read permission)
            console.warn(chalk.yellow(`Could not scan ${path.relative(rootDir, filePath)} for endpoints: ${error.message}`));
        }
    });

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

    // Filter config findings based on high-only flag if needed (e.g., only High CORS)
    const reportConfigFindings = options.highOnly
      ? allConfigFindings.filter(f => f.severity === 'High' || f.severity === 'Critical')
      : allConfigFindings;

    // Filter upload findings (adjust severity filtering as needed)
    const reportUploadFindings = options.highOnly
      ? allUploadFindings.filter(f => f.severity === 'High' || f.severity === 'Critical' || f.severity === 'Medium') // Example: Include Medium for uploads even with --high-only?
      : allUploadFindings;

    // Filter endpoint findings (e.g., keep Medium+ for high-only)
    const reportEndpointFindings = options.highOnly
        ? allEndpointFindings.filter(f => f.severity === 'High' || f.severity === 'Critical' || f.severity === 'Medium') 
        : allEndpointFindings;

    // --- NOW Check Gitignore Status --- 
    gitignoreWarnings = checkGitignoreStatus(rootDir);

    // --- Output Generation ---
    const reportData = { 
        secretFindings: reportSecretFindings, 
        dependencyFindings: reportDependencyFindings, 
        configFindings: reportConfigFindings,
        uploadFindings: reportUploadFindings,
        endpointFindings: reportEndpointFindings
    };

    // Generate JSON if requested
    if (options.output) {
        try {
            const outputJsonData = {
                secrets: reportSecretFindings,
                dependencies: reportDependencyFindings,
                configuration: reportConfigFindings,
                uploads: reportUploadFindings,
                endpoints: reportEndpointFindings
            }
            fs.writeFileSync(options.output, JSON.stringify(outputJsonData, null, 2));
            console.log(`JSON results successfully written to ${options.output}`);
        } catch (error) {
            console.error(`Error writing JSON output file ${options.output}:`, error);
            // Decide if this should be fatal? Maybe not if MD report is also requested.
        }
    }

    // Generate Markdown Report if requested
    if (reportPath) { 
        try {
            // Await the async report generation
            const markdownContent = await generateMarkdownReport(reportData); 
            fs.writeFileSync(reportPath, markdownContent);
            console.log(`Markdown report successfully written to ${reportPath}`);
        } catch (error) {
             console.error(`Error writing Markdown report file ${reportPath}:`, error);
        }
    }

    // Print to console ONLY if neither JSON nor Markdown output was specified
    if (!options.output && !reportPath) {
        
        // Print Configuration Warnings FIRST (after scans, before results)
        if (gitignoreWarnings.length > 0) {
            console.log(chalk.yellow.bold('\n⚠️ Configuration Warnings:')); // Added emoji
            gitignoreWarnings.forEach(warning => {
                const emoji = warning.type === 'MISSING' ? '❓' : '❗'; // Different emojis
                console.log(chalk.yellow(`  ${emoji} ${warning.message}`));
            });
        }

        // Handle Info findings first
        if (infoSecretFindings.length > 0) {
            console.log(chalk.blue.bold('\nInfo:'));
            // Get unique .env files found
            const envFiles = [...new Set(infoSecretFindings.map(f => f.file))];
            envFiles.forEach(file => {
                console.log(`  - Found potential secrets in ${chalk.cyan(file)}. Ensure this file is in .gitignore and not committed to version control.`);
            });
        }

        // Check if any standard findings exist (including config)
        const hasStandardSecrets = reportSecretFindings.length > 0;
        const hasDependencyIssues = reportDependencyFindings.length > 0;
        const hasConfigIssues = reportConfigFindings.length > 0;
        const hasUploadIssues = reportUploadFindings.length > 0;
        const hasEndpointIssues = reportEndpointFindings.length > 0;

        if (hasStandardSecrets || hasDependencyIssues || hasConfigIssues || hasUploadIssues || hasEndpointIssues) {
            // Print standard secrets to console if found
            if (hasStandardSecrets) {
                console.log(chalk.bold('\nPotential Secrets Found:'));
                reportSecretFindings.forEach(finding => {
                    console.log(`  - [${colorSeverity(finding.severity)}] ${finding.type} in ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`);
                });
            }

            // Print dependency findings to console if found
            if (hasDependencyIssues) {
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
            }

            // Print config findings to console if found
            if (hasConfigIssues) {
                console.log(chalk.bold('\nConfiguration Issues Found:'));
                reportConfigFindings.sort((a,b) => severityToSortOrder(b.severity) - severityToSortOrder(a.severity));
                reportConfigFindings.forEach(finding => {
                    console.log(`  - [${colorSeverity(finding.severity)}] ${finding.type}: ${chalk.cyan(finding.file)} - Key: ${chalk.magenta(finding.key)}, Value: ${chalk.yellow(JSON.stringify(finding.value))}`);
                    console.log(chalk.dim(`    > ${finding.message}`));
                });
            }

            // Print upload findings to console if found
            if (hasUploadIssues) {
                console.log(chalk.bold('\nPotential Upload Issues Found:'));
                reportUploadFindings.sort((a,b) => severityToSortOrder(b.severity) - severityToSortOrder(a.severity));
                reportUploadFindings.forEach(finding => {
                    // Customize console output for upload findings
                    console.log(`  - [${colorSeverity(finding.severity)}] ${finding.type} in ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`);
                    console.log(chalk.dim(`    > ${finding.message}`));
                    if (finding.details) {
                         console.log(chalk.dim(`      ${finding.details}`));
                    }
                });
            }

            // Print endpoint findings to console if found
            if (hasEndpointIssues) {
                console.log(chalk.bold('\nPotentially Exposed Endpoints Found:'));
                reportEndpointFindings.sort((a,b) => severityToSortOrder(b.severity) - severityToSortOrder(a.severity));
                reportEndpointFindings.forEach(finding => {
                    console.log(`  - [${colorSeverity(finding.severity)}] ${finding.type} in ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`);
                    console.log(chalk.dim(`    > Path: ${chalk.magenta(finding.path)} - ${finding.message}`));
                    if (finding.details) {
                         console.log(chalk.dim(`      Context: ${finding.details}`));
                    }
                });
            }
        } else {
            // All Clear! Print positive message.
            // Check if we actually scanned for dependencies before saying no vulns found
            const scannedDeps = dependencyInfoList.length > 0;
            console.log(chalk.green.bold('\n✅ No issues found! Keep up the good vibes! 😎'));
            // Optionally add context:
            if (!scannedDeps) {
                 console.log(chalk.gray('  (Dependency vulnerability scan skipped as no supported package manager was detected)'));
            }
        }
    }

    console.log('\nScan complete.');

    // Exit code logic (Phase 1.2 / 3.4)
    // Info findings should NOT affect exit code
    const highSeveritySecrets = reportSecretFindings.some(f => f.severity === 'High');
    const highSeverityDeps = reportDependencyFindings.some(d => d.maxSeverity === 'High' || d.maxSeverity === 'Critical');
    const highSeverityConfig = reportConfigFindings.some(f => f.severity === 'High' || f.severity === 'Critical');
    const highSeverityUploads = reportUploadFindings.some(f => f.severity === 'High' || f.severity === 'Critical' || f.severity === 'Medium');
    const highSeverityEndpoints = reportEndpointFindings.some(f => f.severity === 'High' || f.severity === 'Critical' || f.severity === 'Medium');

    if (options.highOnly && (highSeveritySecrets || highSeverityDeps || highSeverityConfig || highSeverityUploads || highSeverityEndpoints)) {
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