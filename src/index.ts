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
import { checkRateLimitHeuristic, RateLimitFinding } from './scanners/rateLimiting';
import { scanForLoggingIssues, LoggingFinding } from './scanners/logging';
import { scanForHttpClientIssues, HttpClientFinding } from './scanners/httpClient';

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
    let allRateLimitFindings: RateLimitFinding[] = [];
    let allLoggingFindings: LoggingFinding[] = [];
    let allHttpClientFindings: HttpClientFinding[] = [];

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

    // --- Rate Limit Heuristic Check (Phase 6.4 - Revised) ---
    console.log('Checking for presence of known rate limiting packages and API routes...');
    // Pass all parsed dependencies and the files likely containing routes
    allRateLimitFindings = checkRateLimitHeuristic(dependencyInfoList, filesForEndpointScan);
    if (allRateLimitFindings.length > 0) {
        console.log(chalk.yellow('Found API routes but no known rate-limiting package in dependencies. Added project-level advisory.'));
    } else {
        console.log('Rate limiting check passed (either known package found or no routes detected).');
    }

    // --- Logging Scan (Phase 6.5) ---
    console.log(`Scanning ${filesForEndpointScan.length} files for potential logging issues...`);
    filesForEndpointScan.forEach(filePath => {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const findings = scanForLoggingIssues(filePath, content);
            const relativeFindings = findings.map(f => ({ ...f, file: path.relative(rootDir, f.file) }));
            allLoggingFindings = allLoggingFindings.concat(relativeFindings);
        } catch (error: any) {
            console.warn(chalk.yellow(`Could not scan ${path.relative(rootDir, filePath)} for logging issues: ${error.message}`));
        }
    });

    // --- HTTP Client Scan (Phase 6.4.2) ---
    console.log(`Scanning ${filesForEndpointScan.length} files for potential HTTP client issues...`);
    filesForEndpointScan.forEach(filePath => {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const findings = scanForHttpClientIssues(filePath, content);
            const relativeFindings = findings.map(f => ({ ...f, file: path.relative(rootDir, f.file) }));
            allHttpClientFindings = allHttpClientFindings.concat(relativeFindings);
        } catch (error: any) {
            // Avoid crashing if a single file fails
            console.warn(chalk.yellow(`Could not scan ${path.relative(rootDir, filePath)} for HTTP client issues: ${error.message}`));
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

    // Filter rate limit findings (These are 'Low' severity, so they likely won't show with --high-only)
    const reportRateLimitFindings = options.highOnly
        ? [] // Project-level advisory is Low severity, exclude with --high-only
        : allRateLimitFindings;

    // Filter logging findings (update variable names)
    const reportLoggingFindings = options.highOnly
        ? allLoggingFindings.filter(f => f.severity === 'High' || f.severity === 'Critical' || f.severity === 'Medium') // Keep Medium for PII?
        : allLoggingFindings;

    // Filter HTTP client findings (Low severity)
    const reportHttpClientFindings = options.highOnly
        ? allHttpClientFindings.filter(f => f.severity === 'High' || f.severity === 'Critical' || f.severity === 'Medium')
        : allHttpClientFindings;

    // --- NOW Check Gitignore Status --- 
    gitignoreWarnings = checkGitignoreStatus(rootDir);

    // --- Report Generation (Phase 4) ---
    if (reportPath) {
        const reportData = {
            secretFindings: reportSecretFindings,
            dependencyFindings: reportDependencyFindings,
            configFindings: reportConfigFindings,
            uploadFindings: reportUploadFindings,
            endpointFindings: reportEndpointFindings,
            rateLimitFindings: reportRateLimitFindings,
            loggingFindings: reportLoggingFindings,
            httpClientFindings: reportHttpClientFindings,
            gitignoreWarnings: gitignoreWarnings,
            infoSecretFindings: infoSecretFindings
        };
        try {
            const markdownContent = await generateMarkdownReport(reportData);
            fs.writeFileSync(reportPath, markdownContent);
            console.log(chalk.green(`\nMarkdown report generated successfully at ${reportPath}`));
        } catch (error: any) {
            console.error(chalk.red(`\nFailed to generate Markdown report: ${error.message}`));
            process.exit(1);
        }
    }

    // --- JSON Output --- 
    if (options.output) {
        const jsonData = {
            secrets: reportSecretFindings,
            dependencies: reportDependencyFindings,
            configuration: reportConfigFindings,
            uploads: reportUploadFindings,
            endpoints: reportEndpointFindings,
            rateLimiting: reportRateLimitFindings,
            logging: allLoggingFindings, // Use the full list here
            httpClients: reportHttpClientFindings,
            info: infoSecretFindings,
            gitignoreWarnings: gitignoreWarnings,
        };
        try {
            fs.writeFileSync(options.output, JSON.stringify(jsonData, null, 2));
            console.log(chalk.green(`\nJSON output written successfully to ${options.output}`));
        } catch (error: any) {
            console.error(chalk.red(`\nFailed to write JSON output: ${error.message}`));
        }
    }
    
    // --- Console Output (Phase 5.1) ---
    const suppressConsole = !!reportPath || !!options.output;

    if (!suppressConsole) {
        // Gitignore Warnings
        if (gitignoreWarnings.length > 0) {
            console.log(chalk.yellow.bold('\n⚠️ Configuration Warnings:'));
            gitignoreWarnings.forEach(warning => {
                console.log(`  ❓ ${warning.message}`);
            });
        }
        // Info Secrets (.env)
        if (infoSecretFindings.length > 0) {
            console.log(chalk.cyan.bold('\nInfo:'));
            // Get unique .env files found
            const envFiles = [...new Set(infoSecretFindings.map(f => f.file))];
            envFiles.forEach(file => {
                console.log(`  - Found potential secrets in ${chalk.cyan(file)}. Ensure this file is in .gitignore and not committed to version control.`);
            });
        }

        // Combine all reportable (filtered) findings
        const allReportFindings = [
            ...reportSecretFindings,
            ...reportDependencyFindings,
            ...reportConfigFindings,
            ...reportUploadFindings,
            ...reportEndpointFindings,
            ...reportRateLimitFindings,
            ...reportLoggingFindings, 
            ...reportHttpClientFindings
        ];

        if (allReportFindings.length > 0) {
            const severityOrder = severityToSortOrder; 
            const sortedFindings = allReportFindings.sort((a: any, b: any) => {
                const severityDiff = severityOrder(a.severity) - severityOrder(b.severity);
                if (severityDiff !== 0) return severityDiff;
                // Ensure 'file' property exists for sorting
                const fileA = a.file || (a.packageName ? `${a.packageName}@${a.version}` : 'N/A');
                const fileB = b.file || (b.packageName ? `${b.packageName}@${b.version}` : 'N/A');
                return fileA.localeCompare(fileB);
            });

            const groupedFindings: { [key: string]: any[] } = {};
            sortedFindings.forEach((f: any) => { 
                 // ---- TEMPORARY DEBUG LOG (Removed for now) ----
                 // console.log('DEBUG Finding:', JSON.stringify(f)); 
                 // ---------------------------
                 
                let typeKey = 'Other Issues Found'; // Default key (Renamed)
                
                // ---- Grouping Logic v4.1 ----
                if (f.type === 'Potential Unsanitized Error Logging' || f.type === 'Potential PII Logging') {
                    typeKey = 'Potential Logging Issues Found';
                // Ensure exact match for Rate Limit type string from its scanner
                // } else if (f.type === 'Project-Level Rate Limit Advisory') { 
                //     typeKey = 'Project-Level Rate Limit Advisory Found';
                // Use 'name' property for dependencies
                } else if ('name' in f && 'version' in f && 'packageManager' in f) {
                    typeKey = 'Dependencies with Issues Found';
                } else if ('pattern' in f && f.severity !== 'Info') {
                    typeKey = 'Potential Secrets Found';
                } else if (f.type === 'Potential Missing Timeout' && 'library' in f) {
                    typeKey = 'Potential HTTP Client Issues Found';
                 } else if (f.type === 'Potentially Exposed Debug/Admin Endpoint' || 'path' in f) {
                    typeKey = 'Potentially Exposed Endpoints Found';
                } else if (f.type === 'Missing Upload Size Limit' || f.type === 'Missing Upload File Filter' || f.type === 'Generic File Upload Pattern' || 'patternType' in f) {
                    typeKey = 'Potential Upload Issues Found';
                } else if (f.type === 'Permissive CORS' || f.type === 'Insecure Setting' || 'key' in f) {
                    typeKey = 'Configuration Issues Found';
                }

                if (!groupedFindings[typeKey]) groupedFindings[typeKey] = [];
                if (!(typeKey === 'Potential Secrets Found' && f.severity === 'Info')) {
                     groupedFindings[typeKey].push(f);
                }
            });

            // Define the desired order of sections (keep Other as last)
            const sectionOrder = [
                'Potential Secrets Found',
                'Dependencies with Issues Found',
                'Configuration Issues Found',
                'Potential Upload Issues Found',
                'Potentially Exposed Endpoints Found',
                // 'Project-Level Rate Limit Advisory Found', // Removed section title
                'Potential Logging Issues Found',
                'Potential HTTP Client Issues Found',
                'Other Issues Found' // Renamed
            ];

            // Print findings grouped by type
            sectionOrder.forEach(sectionTitle => {
                if (groupedFindings[sectionTitle] && groupedFindings[sectionTitle].length > 0) {
                    console.log(chalk.bold(`\n${sectionTitle}:`));
                    groupedFindings[sectionTitle].forEach(finding => {
                        // ---- Revised Print Logic (Matching Grouping Order) ----
                        if (finding.type === 'Potential Unsanitized Error Logging' || finding.type === 'Potential PII Logging') {
                            // Add file/line for PII, keep simpler format for generic error logging
                            if (finding.type === 'Potential PII Logging') {
                                console.log(`  - [${colorSeverity(finding.severity)}] ${finding.message} in ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`); 
                            } else { // Potential Unsanitized Error Logging
                                // Now also include file/line for unsanitized error logging
                                console.log(`  - [${colorSeverity(finding.severity)}] ${finding.message} in ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`); 
                            }
                            console.log(chalk.dim(`    > ${finding.details}`)); 
                        } else if ('name' in finding && 'version' in finding && 'packageManager' in finding) { 
                            const issues = finding.vulnerabilities?.length > 0 
                                ? `${finding.vulnerabilities.length} vulnerabilities (${finding.vulnerabilities.map((v: any) => v.id).slice(0, 3).join(', ')}...)`
                                : finding.error || 'No known vulnerabilities or error checking OSV';
                             const depSeverity = finding.maxSeverity || (finding.error ? 'Medium' : 'None'); 
                            console.log(`  - [${colorSeverity(depSeverity)}] ${chalk.magenta(finding.name)}@${chalk.gray(finding.version)}: ${issues}`);
                        } else if ('pattern' in finding) { // Secrets 
                             console.log(`  - [${colorSeverity(finding.severity)}] ${finding.type} in ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`);
                         } else if (finding.type === 'Potential Missing Timeout' && 'library' in finding) { 
                            console.log(`  - [${colorSeverity(finding.severity)}] ${finding.type} (${finding.library}) in ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`);
                            console.log(chalk.dim(`    > ${finding.message}`));
                             if (finding.details) {
                                 console.log(chalk.dim(`      ${finding.details}`));
                             }
                        } else if (finding.type === 'Potentially Exposed Debug/Admin Endpoint' || 'path' in finding) { 
                            console.log(`  - [${colorSeverity(finding.severity)}] ${finding.message} in ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`);
                            console.log(chalk.dim(`    > Path: ${chalk.magenta(finding.path)} - ${finding.details}`));
                        } else if (finding.type === 'Missing Upload Size Limit' || finding.type === 'Missing Upload File Filter' || finding.type === 'Generic File Upload Pattern' || 'patternType' in finding) { 
                            console.log(`  - [${colorSeverity(finding.severity)}] ${finding.message} in ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`);
                            console.log(chalk.dim(`    > ${finding.details}`));
                        } else if (finding.type === 'Permissive CORS' || finding.type === 'Insecure Setting' || 'key' in finding) { 
                            console.log(`  - [${colorSeverity(finding.severity)}] ${finding.description || finding.type}: ${chalk.cyan(finding.file)} - Key: ${chalk.magenta(finding.key)}, Value: ${chalk.yellow(JSON.stringify(finding.value))}`);
                            console.log(chalk.dim(`    > ${finding.message}`));
                        } else { // Fallback for Other Issues Found
                            // Special handling for our Project-Level Rate Limit Advisory
                            if (finding.type === 'Project-Level Rate Limit Advisory') {
                                console.log(`  - [${colorSeverity(finding.severity)}] ${finding.message}`);
                                console.log(chalk.dim(`    > Suggestion: ${finding.details}`)); 
                            } else {
                                // Generic fallback formatting for truly other/unknown issues
                                const severity = finding.severity || 'Unknown';
                                const message = finding.message || 'No message available';
                                const file = finding.file || 'N/A';
                                const line = finding.line ? `:${chalk.yellow(String(finding.line))}` : '';
                                const type = finding.type ? `(${finding.type}) ` : '';
                                console.log(`  - [${colorSeverity(severity)}] ${type}Issue detected in ${chalk.cyan(file)}${line}`);
                                console.log(chalk.dim(`    > ${message}`));
                                // Optionally add details if present
                                if (finding.details) {
                                    console.log(chalk.dim(`    > Details: ${finding.details}`));
                                }
                            }
                        }
                    });
                }
            });
        } else {
            // All Clear! Print positive message.
            console.log(chalk.green.bold('\n✅ No significant issues found! Keep up the good vibes! 😎'));
        }

    } else {
        // Combine ALL findings (before filtering) to check if *any* exist
        const anyFindingsExist = 
            allSecretFindings.length > 0 || 
            allDependencyFindings.length > 0 || 
            allConfigFindings.length > 0 || 
            allUploadFindings.length > 0 || 
            allEndpointFindings.length > 0 || 
            allRateLimitFindings.length > 0 || 
            allLoggingFindings.length > 0 || 
            allHttpClientFindings.length > 0;

        // Message indicating suppression only if findings exist
        if (anyFindingsExist) {
             console.log(chalk.dim('\n(Console output suppressed due to report/output file generation.)'));
        }
    }
    
    // --- Exit Code (Phase 1.2 / 5.2) ---
    const hasHighSeverityIssue = 
        reportSecretFindings.some(f => f.severity === 'High' || f.severity === 'Critical') ||
        reportDependencyFindings.some(dep => dep.maxSeverity === 'High' || dep.maxSeverity === 'Critical') ||
        reportConfigFindings.some(f => f.severity === 'High' || f.severity === 'Critical') ||
        reportUploadFindings.some(f => f.severity === 'High' || f.severity === 'Critical') || 
        reportEndpointFindings.some(f => f.severity === 'High' || f.severity === 'Critical') || 
        // Use the correct filtered list name here
        reportLoggingFindings.some(f => f.severity === 'High' || f.severity === 'Critical' || f.severity === 'Medium'); // Consider Medium PII? 
        // Note: RateLimit, HTTPClient currently don't have High/Critical that affect exit code
        

    // --- Final Summary --- 
    console.log(chalk.bold('\n--- Scan Summary ---'));
    const summaryPoints = [
        { emoji: '🔑', label: 'Secrets', count: reportSecretFindings.length },
        { emoji: '📦', label: 'Dependencies', count: reportDependencyFindings.length },
        { emoji: '⚙️', label: 'Configuration', count: reportConfigFindings.length },
        { emoji: '⬆️', label: 'Uploads', count: reportUploadFindings.length },
        { emoji: '🔌', label: 'Endpoints', count: reportEndpointFindings.length },
        { emoji: '📝', label: 'Logging', count: reportLoggingFindings.length }, 
        { emoji: '🌐', label: 'HTTP Clients', count: reportHttpClientFindings.length },
        { emoji: '⏳', label: 'Rate Limit Advisory', count: reportRateLimitFindings.length }, // Will be 0 or 1
        { emoji: '💡', label: 'Info (.env)', count: infoSecretFindings.length },
        { emoji: '⚠️', label: 'Config Warnings', count: gitignoreWarnings.length },
    ];

    // Calculate padding for alignment
    let maxLabelWidth = 0;
    summaryPoints.forEach(point => {
        if (point.count > 0) {
            const labelWidth = point.label.length; // Emoji width can vary, focus on label
            if (labelWidth > maxLabelWidth) {
                maxLabelWidth = labelWidth;
            }
        }
    });
    const firstColWidth = maxLabelWidth + 4; // emoji + space + label + space buffer

    summaryPoints.forEach(point => {
        if (point.count > 0) {
            const labelPart = `${point.emoji} ${point.label}`;
            console.log(`  ${labelPart.padEnd(firstColWidth)} ${chalk.yellow(point.count)}`);
        } else {
            // Optionally hide sections with 0 findings, or show them dimmed
            // console.log(chalk.dim(`  ${point.emoji} ${point.label}: 0`));
        }
    });

    const totalReported = summaryPoints.reduce((sum, point) => sum + point.count, 0);
    if (totalReported > 0) {
        console.log(chalk.cyan('\nPlease scroll up to review the detailed findings.'));
    } else if (!suppressConsole) {
        // If no findings were reported and console wasn't suppressed, reiterate the all-clear message
        console.log(chalk.green.bold('✅ No issues found in the scan.'));
    }

    if (options.highOnly && hasHighSeverityIssue) {
        console.log(chalk.red.bold('\nScan complete. High severity issues found. Exiting with code 1.'));
        process.exit(1);
    } else {
        console.log('\nScan complete.');
        process.exit(0);
    }

  });

// Helper for sorting console output - Add Info level
function severityToSortOrder(severity: FindingSeverity | SecretFinding['severity'] | UploadFinding['severity'] | LoggingFinding['severity'] | EndpointFinding['severity'] | RateLimitFinding['severity'] | HttpClientFinding['severity']): number {
    switch (severity) {
        case 'Critical': return 0;
        case 'High': return 1;
        case 'Medium': return 2;
        case 'Low': return 3;
        case 'None': return 4;
        case 'Info': return 5;
        default: return 6;
    }
}

program.parse(process.argv);
