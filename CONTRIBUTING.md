# Contributing to VibeSafe 🛡️

Thanks for your interest in improving VibeSafe!  
We're an open-source security CLI built for developers — fast, useful, and community-driven.

Whether you're fixing a typo, improving performance, adding new scanners, or suggesting a feature, we welcome your input.

---

## 💡 How to Contribute

1. **Fork the repo**
2. **Clone your fork and create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Run tests** (if applicable)
5. **Open a Pull Request (PR)** with a clear description of what you changed and why

## 📏 Guidelines
Keep PRs focused and minimal — smaller is better

Avoid introducing new dependencies unless absolutely necessary

Write clear, readable code (preferably TypeScript where applicable)

Add comments or docs for any non-obvious logic

If adding a new scanner or rule, explain the security impact or use case

## 🧪 Testing (Basic)
Most of VibeSafe is modular and easy to test with sample files.
You can test your changes by running:

```bash
npm run build
npm link
vibesafe scan ./test-project
```

If you're improving output formats or adding rules, try --output and --report modes to check formatting.

## Codebase Overview

This repository contains a TypeScript-based CLI tool named VibeSafe. It scans Node/JavaScript projects for a variety of security issues and can check packages before installing them. The key features—secret scanning, dependency vulnerability checks, configuration inspection, upload validation, endpoint exposure detection, rate-limit heuristics, logging analysis, HTTP client checks, and optional AI suggestions—are summarized in the README.

### Project Structure

```
src/
├── index.ts            # CLI entry point
├── scanners/           # Individual scanners (secrets, dependencies, config, etc.)
├── reporting/          # Markdown/AI report generation
├── installer/          # "vibesafe install" helpers
├── utils/              # File traversal & ignore handling
test-data/              # Sample projects/files for testing
```

### CLI Commands
Defined with Commander in `src/index.ts`. The `scan` command accepts optional output/report flags and supports `--high-only` filtering. The `install` command performs heuristic checks before running `npm install`.

### File Traversal
`src/utils/fileTraversal.ts` loads ignore patterns (including `.vibesafeignore`) and walks the directory tree while checking `.gitignore` for common secrets.

### Scanners
Located in `src/scanners/`. Each scanner returns a list of findings with a severity level. Examples include:

*   **Secrets** – Regex/entropy scanning with special handling for `.env` files.
*   **Dependencies** – Detects package managers, parses manifests, and queries the OSV database for CVEs.
*   **Configuration, Uploads, Endpoints, Rate Limiting, Logging, and HTTP Client scanners** each analyze code or configs for specific issues.

### Reporting
Markdown report generation with optional OpenAI-powered suggestions is in `src/reporting/markdown.ts` and `src/reporting/aiSuggestions.ts` (if AI suggestions are implemented).

### Installer Heuristics
`src/installer/heuristicChecks.ts` checks package age, download counts, README quality, license presence, and repository links to warn about suspicious packages.

### Usage

The README shows typical commands:

```bash
vibesafe scan
vibesafe scan ./path/to/project
vibesafe scan -r scan-report.md        # Markdown report
vibesafe scan --high-only              # Only high severity issues
```

For installation checks:

```bash
vibesafe install <package-name>
```
which runs age/download/license heuristics and prompts before installing.

### Next Steps for Learning

1.  **Understand each scanner.** Explore `src/scanners/` to see how patterns are detected (regex, AST parsing via `@typescript-eslint`).
2.  **Review the file traversal logic** to learn how `.vibesafeignore` and `.gitignore` rules are applied.
3.  **Examine the installer heuristics** to see how package metadata is fetched and analyzed.
4.  **Build and run locally** (`npm run build` then `npm link`) to test the CLI on the provided `test-data` projects.
5.  **Check TODOs in the code** for areas under development: e.g., full lockfile parsing in dependency scanning and additional heuristics in the installer.

The repository offers a modular foundation for a security-focused CLI, and diving into each scanner will help you understand how to extend or refine VibeSafe's checks.

## 📛 Brand Reminder
The name VibeSafe™ is a trademark of Secret Society LLC.
Forks and derivative tools are welcome under the MIT License, but please use a different name and logo for your project.

If you'd like to collaborate, contribute under the official name, or build something commercial on top of VibeSafe, reach out:
📬 vibesafepackage@gmail.com

## 🤝 Code of Conduct
Be respectful. This project is about making security tools accessible, not gatekeeping. We welcome newcomers, learners, and veterans alike.

## 🚀 Ready to go?
Open your PR, and let's make security more developer-friendly — together.

Stay safe. Stay vibey. ✨