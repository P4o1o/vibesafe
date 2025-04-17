# VibeSafe ✨🛡️

A CLI tool to scan your codebase for security vibes.

VibeSafe helps developers quickly check their projects for common security issues like exposed secrets, outdated dependencies with known vulnerabilities (CVEs), and generates helpful reports.

## Features

*   **Secret Scanning:** Detects potential secrets using regex patterns (AWS Keys, JWTs, SSH Keys, generic high-entropy strings) and specifically flags secrets found in `.env` files.
*   **Dependency Scanning:** Parses `package.json` (for npm/yarn projects) and checks dependencies against the OSV.dev vulnerability database for known CVEs.
*   **Configuration Scanning:** Checks JSON and YAML files for common insecure settings (e.g., `DEBUG = true`, `devMode = true`, permissive CORS like `origin: '*'`).
*   **HTTP Client Issues:** Detects potential missing timeout or cancellation configurations in calls using `axios`, `fetch`, `got`, and `request`. (*See Limitations below*).
*   **Unvalidated Upload Detection:** Identifies potential missing file size/type restrictions in common upload libraries (`multer`, `formidable`, `express-fileupload`, `busboy`) and generic patterns (`new FormData()`, `<input type="file">`).
*   **Exposed Endpoint Detection:** Flags potentially sensitive endpoints (e.g., `/admin`, `/debug`, `/status`, `/info`, `/metrics`) in Express/Node.js applications using common routing patterns or string literals.
*   **Rate Limit Check (Heuristic):** Suggests reviewing rate limiting if Express/Node.js routes are detected in a file without an `express-rate-limit` import.
*   **Improper Logging Detection:** Flags potential logging of full error objects (e.g., `console.error(err)`), which can leak stack traces, and detects logging of potentially sensitive data based on keywords (e.g., `password`, `email`, `token`).
*   **Multiple Output Formats:** Provides results via console output (with colors!), JSON (`--output`), or a Markdown report (`--report` with default `VIBESAFE-REPORT.md`).
*   **AI-Powered Suggestions (Optional):** Generates fix suggestions in the Markdown report using OpenAI (requires API key).
*   **Filtering:** Focus on high-impact issues using `--high-only`.
*   **Customizable Ignores:** Use a `.vibesafeignore` file (similar syntax to `.gitignore`) to exclude specific files or directories from the scan.

## Installation

```