# VibeSafe ✨🛡️

A CLI tool to scan your codebase for security vibes.

VibeSafe helps developers quickly check their projects for common security issues like exposed secrets, outdated dependencies with known vulnerabilities (CVEs), and generates helpful reports.

## Features (MVP)

*   **Secret Scanning:** Detects potential secrets (API keys, credentials) using regex patterns and entropy analysis.
*   **Dependency Scanning:** Parses package manifests (currently `package.json`) and checks dependencies against the OSV.dev vulnerability database.
*   **Configuration Scanning:** Checks configuration files (JSON, YAML) for common insecure settings (e.g., `DEBUG=true`, permissive CORS).
*   **Unvalidated Upload Detection:** Identifies potential missing file size/type restrictions in common upload libraries (e.g., `multer`, `formidable`) and generic patterns (`FormData`, `<input type="file">`).
*   **Exposed Endpoint Detection:** Flags potentially sensitive endpoints (e.g., `/admin`, `/debug`, `/status`) based on common patterns.
*   **Multiple Output Formats:** Provides results via console output (with colors!), JSON (`--output`), or a Markdown report (`--report`).
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