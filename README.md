# VibeSafe ✨🛡️

A CLI tool to scan your codebase for security vibes.

VibeSafe helps developers quickly check their projects for common security issues like exposed secrets, outdated dependencies with known vulnerabilities (CVEs), and generates helpful reports.

## Features

*   **Secret Scanning:** Detects potential secrets using regex patterns (AWS Keys, JWTs, SSH Keys, generic high-entropy strings) and specifically flags secrets found in `.env` files.
*   **Dependency Scanning:** Parses `package.json` (for npm/yarn projects) and checks dependencies against the OSV.dev vulnerability database for known CVEs. *(Note: Currently only scans direct dependencies listed in `package.json`. Lockfile analysis for precise versions and transitive dependencies is planned for a future update.)*
*   **Configuration Scanning:** Checks JSON and YAML files for common insecure settings (e.g., `DEBUG = true`, `devMode = true`, permissive CORS like `origin: '*'`)
*   **HTTP Client Issues:** Detects potential missing timeout or cancellation configurations in calls using `axios`, `fetch`, `got`, and `request`. (*See Limitations below*).
*   **Unvalidated Upload Detection:** Identifies potential missing file size/type restrictions in common upload libraries (`multer`, `formidable`, `express-fileupload`, `busboy`) and generic patterns (`new FormData()`, `<input type="file">`).
*   **Exposed Endpoint Detection:** Flags potentially sensitive endpoints (e.g., `/admin`, `/debug`, `/status`, `/info`, `/metrics`) in Express/Node.js applications using common routing patterns or string literals.
*   **Rate Limit Check (Heuristic):** Issues a project-level advisory if API routes are detected but no known rate-limiting package (e.g., `express-rate-limit`, `@upstash/ratelimit`) is found in dependencies.
*   **Improper Logging Detection:** Flags potential logging of full error objects (e.g., `console.error(err)`), which can leak stack traces, and detects logging of potentially sensitive data based on keywords (e.g., `password`, `email`, `token`).
*   **Multiple Output Formats:** Provides results via console output (with colors!), JSON (`--output`), or a Markdown report (`--report` with default `VIBESAFE-REPORT.md`).
*   **AI-Powered Suggestions (Optional):** Generates fix suggestions in the Markdown report using OpenAI (requires API key).
*   **Filtering:** Focus on high-impact issues using `--high-only`.
*   **Customizable Ignores:** Use a `.vibesafeignore` file (similar syntax to `.gitignore`) to exclude specific files or directories from the scan.

## Installation

```bash
npm install -g vibesafe 
```

*(Note: Currently, for local development, use `npm link` after building)*

## Usage

**Basic Scan (Current Directory):**

```bash
vibesafe scan
```

**Scan a Specific Directory:**

```bash
vibesafe scan ./path/to/your/project
```

**Output to JSON:**

```bash
vibesafe scan -o scan-results.json
```

**Generate Markdown Report:**

To generate a Markdown report, use the `-r` or `--report` flag. You can optionally provide a filename. If no filename is given, it defaults to `VIBESAFE-REPORT.md` in the scanned directory.

*With a specific filename:*
```bash
vibesafe scan -r scan-report.md
```

*Using the default filename (`VIBESAFE-REPORT.md`):*
```bash
vibesafe scan -r
# or
vibesafe scan --report 
```

**Generate AI Report (Requires API Key):**

To generate fix suggestions in the Markdown report, you need an OpenAI API key.

1.  Create a `.env` file in the root of the directory where you run `vibesafe` (or in the project root if running locally during development).
2.  Add your key to the `.env` file:
    ```
    OPENAI_API_KEY=sk-YourActualOpenAIKeyHere
    ```
3.  Run the scan with the report flag:
    ```bash
vibesafe scan -r ai-report.md
    ```

**Show Only High/Critical Issues:**

```bash
vibesafe scan --high-only
```

## Ignoring Files (.vibesafeignore)

Create a `.vibesafeignore` file in the root of the directory being scanned. Add file paths or glob patterns (one per line) to exclude them from the scan. The syntax is the same as `.gitignore`.

**Example `.vibesafeignore**:

```
# Ignore all test data
test-data/

# Ignore a specific configuration file
config/legacy-secrets.conf

# Allow scanning a specific .env file if needed (overrides default info behavior)
# !.env.production 
```

## License

This project uses a custom proprietary license. Please see the [LICENSE](LICENSE) file for details. TL;DR: Free to use, source visible, but no modification, copying, or redistribution allowed. 