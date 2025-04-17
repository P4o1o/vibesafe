import { SecretFinding } from '../scanners/secrets';
import { DependencyFinding, FindingSeverity } from '../scanners/dependencies';
import { ConfigFinding } from '../scanners/configuration';
import { UploadFinding } from '../scanners/uploads';
import { EndpointFinding } from '../scanners/endpoints';
import { RateLimitFinding } from '../scanners/rateLimiting';
import { ErrorLoggingFinding } from '../scanners/logging';
import { HttpClientFinding } from '../scanners/httpClient';
// Import the real function (or placeholder) from its own file
import { getAiFixSuggestions } from './aiSuggestions'; 
import path from 'path';

// Helper to map severities for consistent ordering/counting
const severityOrder: Record<FindingSeverity | SecretFinding['severity'], number> = {
    'Critical': 5,
    'High': 4,
    'Medium': 3,
    'Low': 2,
    'Info': 1,
    'None': 0
};

interface ReportData {
    secretFindings: SecretFinding[];
    dependencyFindings: DependencyFinding[];
    configFindings: ConfigFinding[];
    uploadFindings: UploadFinding[];
    endpointFindings: EndpointFinding[];
    rateLimitFindings: RateLimitFinding[];
    errorLoggingFindings: ErrorLoggingFinding[];
    httpClientFindings: HttpClientFinding[];
}

// --- Remove Placeholder AI Suggestion Function ---
/* 
async function getAiFixSuggestions(reportData: ReportData): Promise<string> {
    // ... (placeholder code removed) ...
}
*/
// --- End Remove Placeholder ---

/**
 * Generates a Markdown report from scan findings (async).
 * @param data Object containing secret, dependency, config, and upload findings.
 * @returns A Promise resolving to a string containing the Markdown report.
 */
export async function generateMarkdownReport(data: ReportData): Promise<string> {
    const { secretFindings, dependencyFindings, configFindings, uploadFindings, endpointFindings, rateLimitFindings, errorLoggingFindings, httpClientFindings } = data;

    // --- Calculate Summary --- 
    let totalIssues = 0;
    const severityCounts: { [key in FindingSeverity | 'Medium' | 'Low']: number } = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
        Info: 0,
        None: 0
    };

    secretFindings.forEach(f => {
        if (severityCounts[f.severity as keyof typeof severityCounts] !== undefined) {
             severityCounts[f.severity as keyof typeof severityCounts]++;
        }
        totalIssues++;
    });
    dependencyFindings.forEach(f => {
        if (f.vulnerabilities.length > 0) {
             // Count each vulnerable dependency as one issue, using its max severity
             if (severityCounts[f.maxSeverity] !== undefined) {
                 severityCounts[f.maxSeverity]++;
             }
            totalIssues++; 
        } else if (f.error) {
            // Optionally count errors as issues? For now, no.
        }
    });
    configFindings.forEach(f => {
        severityCounts[f.severity]++;
        totalIssues++;
    });
    uploadFindings.forEach(f => {
        severityCounts[f.severity]++;
        totalIssues++;
    });
    endpointFindings.forEach(f => {
        severityCounts[f.severity]++;
        totalIssues++;
    });
    rateLimitFindings.forEach(f => {
        severityCounts[f.severity]++;
        totalIssues++;
    });
    errorLoggingFindings.forEach(f => {
        severityCounts[f.severity]++;
        totalIssues++;
    });
    httpClientFindings.forEach(f => {
        severityCounts[f.severity]++;
        totalIssues++;
    });

    const summaryParts = [
        `Total Issues: ${totalIssues} (`,
        Object.entries(severityCounts)
              .filter(([severity, count]) => count > 0 && severity !== 'None')
              .sort(([sevA], [sevB]) => severityOrder[sevB as FindingSeverity] - severityOrder[sevA as FindingSeverity])
              .map(([severity, count]) => `${count} ${severity}`)
              .join(', '),
        `)`
    ].join('');

    // --- Build Details Table --- 
    let detailsTable = `| Finding Type      | Severity | Location                         | Details                                      |
| ----------------- | -------- | -------------------------------- | -------------------------------------------- |
`;

    // Combine and sort findings for the table
    const allFindings = [
        ...secretFindings.map(f => ({ ...f, sortKey: severityOrder[f.severity], findingCategory: 'Secret' as const })),
        ...dependencyFindings.filter(f => f.vulnerabilities.length > 0).map(f => ({ ...f, sortKey: severityOrder[f.maxSeverity], findingCategory: 'Dependency' as const })),
        ...configFindings.map(f => ({ ...f, sortKey: severityOrder[f.severity], findingCategory: 'Configuration' as const })),
        ...uploadFindings.map(f => ({ ...f, sortKey: severityOrder[f.severity], findingCategory: 'Upload' as const })),
        ...endpointFindings.map(f => ({ ...f, sortKey: severityOrder[f.severity], findingCategory: 'Endpoint' as const })),
        ...rateLimitFindings.map(f => ({ ...f, sortKey: severityOrder[f.severity], findingCategory: 'RateLimit' as const })),
        ...errorLoggingFindings.map(f => ({ ...f, sortKey: severityOrder[f.severity], findingCategory: 'Logging' as const })),
        ...httpClientFindings.map(f => ({ ...f, sortKey: severityOrder[f.severity], findingCategory: 'HttpClient' as const }))
    ].sort((a, b) => b.sortKey - a.sortKey);

    allFindings.forEach(finding => {
        const severity = finding.findingCategory === 'Dependency' ? finding.maxSeverity : finding.severity;
        let location = '';
        let details = '';

        switch(finding.findingCategory) {
            case 'Secret':
                // Escape pipe characters in file paths for Markdown table
                const escapedFile = finding.file.replace(/\|/g, '\\|');
                location = `${escapedFile}:${finding.line}`;
                details = `${finding.type} (${finding.type === 'High Entropy String' ? 'Entropy' : 'Pattern'})`;
                break;
            case 'Dependency':
                location = `${finding.name}@${finding.version}`;
                const cveIds = finding.vulnerabilities.map(v => v.id).join(', ');
                details = `${finding.vulnerabilities.length} vulnerabilities (${cveIds})`;
                break;
            case 'Configuration':
                 location = finding.file.replace(/\|/g, '\\|');
                 details = `Key: ${finding.key}, Value: ${JSON.stringify(finding.value)} (${finding.type})`;
                 break;
            case 'Upload':
                const escapedUploadFile = finding.file.replace(/\|/g, '\\|');
                location = `${escapedUploadFile}:${finding.line}`;
                details = `${finding.type}: ${finding.message}`;
                if (finding.details) {
                     details += ` (${finding.details.substring(0, 100)}${finding.details.length > 100 ? '...' : ''})`;
                }
                break;
            case 'Endpoint':
                const escapedEndpointFile = finding.file.replace(/\|/g, '\\|');
                location = `${escapedEndpointFile}:${finding.line}`;
                details = `${finding.type}: Path=\`${finding.path}\``;
                if (finding.details) {
                    details += ` (Context: ${finding.details.substring(0, 80)}${finding.details.length > 80 ? '...' : ''}`;
                }
                break;
            case 'RateLimit':
                const escapedRateLimitFile = finding.file.replace(/\|/g, '\\|');
                location = `${escapedRateLimitFile}:${finding.line}`;
                details = finding.message;
                if (finding.details) {
                    details += ` (${finding.details.substring(0, 100)}${finding.details.length > 100 ? '...' : ''})`;
                }
                break;
            case 'Logging':
                const escapedLoggingFile = finding.file.replace(/\|/g, '\\|');
                location = `${escapedLoggingFile}:${finding.line}`;
                details = finding.message;
                if (finding.details) {
                    details += ` (${finding.details.substring(0, 100)}${finding.details.length > 100 ? '...' : ''})`;
                }
                break;
            case 'HttpClient':
                const escapedHttpClientFile = finding.file.replace(/\|/g, '\\|');
                location = `${escapedHttpClientFile}:${finding.line}`;
                details = `${finding.type} (${finding.library}): ${finding.message}`;
                if (finding.details) {
                    details += ` (${finding.details.substring(0, 100)}${finding.details.length > 100 ? '...' : ''})`;
                }
                break;
        }
        detailsTable += `| ${finding.findingCategory} | ${severity} | ${location} | ${details} |
`;
    });

    // --- Get AI Suggestions ---
    const aiSuggestions = await getAiFixSuggestions(data);

    // --- Assemble Report --- 
    const report = `
# VibeSafe Report

## Summary
${summaryParts}

## Details
${detailsTable}
## Fix Suggestions

${aiSuggestions}
`;

    return report.trim();
} 