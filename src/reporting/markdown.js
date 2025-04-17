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
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateMarkdownReport = generateMarkdownReport;
// Import the real function (or placeholder) from its own file
const aiSuggestions_1 = require("./aiSuggestions");
// Helper to map severities for consistent ordering/counting
const severityOrder = {
    'Critical': 5,
    'High': 4,
    'Medium': 3,
    'Low': 2,
    'None': 1
};
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
function generateMarkdownReport(data) {
    return __awaiter(this, void 0, void 0, function* () {
        const { secretFindings, dependencyFindings } = data;
        // --- Calculate Summary --- 
        let totalIssues = 0;
        const severityCounts = {
            Critical: 0,
            High: 0,
            Medium: 0,
            Low: 0,
            None: 0 // Should not be shown in summary, but track for completeness
        };
        secretFindings.forEach(f => {
            severityCounts[f.severity]++;
            totalIssues++;
        });
        dependencyFindings.forEach(f => {
            if (f.vulnerabilities.length > 0) {
                // Count each vulnerable dependency as one issue, using its max severity
                severityCounts[f.maxSeverity]++;
                totalIssues++;
            }
            else if (f.error) {
                // Optionally count errors as issues? For now, no.
            }
        });
        const summaryParts = [
            `Total Issues: ${totalIssues} (`,
            Object.entries(severityCounts)
                .filter(([severity, count]) => count > 0 && severity !== 'None')
                .sort(([sevA], [sevB]) => severityOrder[sevB] - severityOrder[sevA])
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
            ...secretFindings.map(f => (Object.assign(Object.assign({}, f), { sortKey: severityOrder[f.severity], isSecret: true }))),
            ...dependencyFindings.filter(f => f.vulnerabilities.length > 0).map(f => (Object.assign(Object.assign({}, f), { sortKey: severityOrder[f.maxSeverity], isSecret: false })))
        ].sort((a, b) => b.sortKey - a.sortKey);
        allFindings.forEach(finding => {
            if (finding.isSecret) {
                const sf = finding;
                // Escape pipe characters in file paths for Markdown table
                const escapedFile = sf.file.replace(/\|/g, '\\|');
                detailsTable += `| ${escapedFile} | line ${sf.line} | Secret: ${sf.type} | ${sf.severity} | ${sf.type === 'High Entropy String' ? '(Entropy)' : '(Pattern)'} |
`;
            }
            else {
                const df = finding;
                const cveIds = df.vulnerabilities.map(v => v.id).join(', ');
                detailsTable += `| ${df.name} | ${df.version} | Dependency Vuln | ${df.maxSeverity} | ${cveIds} |
`;
            }
        });
        // --- Get AI Suggestions ---
        const aiSuggestions = yield (0, aiSuggestions_1.getAiFixSuggestions)(data);
        // --- Assemble Report --- 
        const report = `
# VibeShield Report

## Summary
${summaryParts}

## Details
${detailsTable}
## Fix Suggestions

${aiSuggestions}
`;
        return report.trim();
    });
}
