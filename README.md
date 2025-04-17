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
*   **Improper Error Logging Detection:** Flags potential logging of full error objects (e.g., `console.error(err)`, `logger.error(e)`), which can leak stack traces.
*   **Multiple Output Formats:** Provides results via console output (with colors!), JSON (`--output`), or a Markdown report (`--report` with default `VIBESAFE-REPORT.md`).
*   **AI-Powered Suggestions (Optional):** Generates fix suggestions in the Markdown report using OpenAI (requires API key).
*   **Filtering:** Focus on high-impact issues using `--high-only`.
*   **Customizable Ignores:** Use a `.vibesafeignore` file (similar syntax to `.gitignore`) to exclude specific files or directories from the scan.

## Installation

```bash
# Assuming publication to npm eventually
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

```bash
# Generate report with a specific name
vibesafe scan -r my-report.md

# Generate report with the default name (VIBESAFE-REPORT.md in the scanned directory)
vibesafe scan -r 
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
    # Use default name VIBESAFE-REPORT.md
    vibesafe scan -r

    # Or specify a name
    vibesafe scan -r vibesafe-ai-report.md 
    ```

**Show Only High/Critical Issues:**

```bash
vibesafe scan --high-only
```

## Limitations

*   **Superagent Timeouts:** The check for missing timeouts in the `superagent` HTTP client library is currently disabled due to complexities in accurately detecting chained method calls (like `.timeout()`) using AST. Calls using `superagent` will not be flagged for missing timeouts at this time. This is planned for a future enhancement.
*   **Dynamic Configuration:** Checks rely on static analysis (AST parsing, regex). Timeouts or security settings configured dynamically (e.g., read from environment variables at runtime and passed into client options) may not be detected.
*   **Rate Limiting:** The check is a heuristic based on the presence of route definitions and the *absence* of a specific import (`express-rate-limit`). It does not guarantee that rate limiting is actually missing or insufficient if implemented differently.
*   **Authentication Checks:** Exposed endpoint detection does not currently verify if proper authentication or authorization middleware is applied to flagged routes.

## Ignoring Files (.vibesafeignore)

Create a `.vibesafeignore` file in the root of the directory being scanned. Add file paths or glob patterns (one per line) to exclude them from the scan. The syntax is the same as `.gitignore`.

**Example `.vibesafeignore**:**

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