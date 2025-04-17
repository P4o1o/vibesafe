import { SecretFinding } from '../scanners/secrets';
import { DependencyFinding, FindingSeverity } from '../scanners/dependencies';
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
 * @param data Object containing secret and dependency findings.
 * @returns A Promise resolving to a string containing the Markdown report.
 */
export async function generateMarkdownReport(data: ReportData): Promise<string> {
    const { secretFindings, dependencyFindings } = data;

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
    let detailsTable = `| File / Dependency | Location / Version | Issue Type       | Severity | CVEs / Pattern |
| ----------------- | ------------------ | ---------------- | -------- | -------------- |
`;

    // Combine and sort findings for the table (e.g., by severity)
    const allFindings = [
        ...secretFindings.map(f => ({ ...f, sortKey: severityOrder[f.severity], isSecret: true })),
        ...dependencyFindings.filter(f => f.vulnerabilities.length > 0).map(f => ({ ...f, sortKey: severityOrder[f.maxSeverity], isSecret: false }))
    ].sort((a, b) => b.sortKey - a.sortKey);

    allFindings.forEach(finding => {
        if (finding.isSecret) {
            const sf = finding as SecretFinding;
            // Escape pipe characters in file paths for Markdown table
            const escapedFile = sf.file.replace(/\|/g, '\\|');
            detailsTable += `| ${escapedFile} | line ${sf.line} | Secret: ${sf.type} | ${sf.severity} | ${sf.type === 'High Entropy String' ? '(Entropy)' : '(Pattern)'} |
`;
        } else {
            const df = finding as DependencyFinding;
            const cveIds = df.vulnerabilities.map(v => v.id).join(', ');
            detailsTable += `| ${df.name} | ${df.version} | Dependency Vuln | ${df.maxSeverity} | ${cveIds} |
`;
        }
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