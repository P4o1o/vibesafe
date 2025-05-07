# VibeSafe ✨🛡️

A CLI tool to scan your codebase for security vibes.

VibeSafe helps developers quickly check their projects for common security issues like exposed secrets, outdated dependencies with known vulnerabilities (CVEs), and generates helpful reports.

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)


## ✨ Features

- 🔐 **Secret Scanning**  
  Flags AWS keys, JWTs, SSH keys, high-entropy strings, and secrets in `.env` files.

- 📦 **Dependency Vulnerability Detection**  
  Checks `package.json` dependencies against the [OSV.dev](https://osv.dev) vulnerability database. *(Direct deps only for now — lockfile support coming soon).*

- ⚙️ **Insecure Config Detection**  
  Scans JSON/YAML for flags like `DEBUG=true`, `devMode`, permissive CORS, etc.

- 🌐 **HTTP Client Scan**  
  Detects missing timeouts or abort controllers in `axios`, `fetch`, `got`, etc.

- 📤 **Upload Validation Check**  
  Warns on lack of file size/type checks in `multer`, `formidable`, etc.

- 🔎 **Exposed Endpoint Detection**  
  Flags risky endpoints like `/admin`, `/debug`, or `/metrics`, including for **Next.js API routes**.

- 🚫 **Missing Rate Limiting (Heuristic)**  
  Warns if your project has API routes but no known rate-limit package installed.

- 🪵 **Improper Logging Patterns**  
  Finds logs that may leak sensitive info or log full error stacks unsafely.

- 📄 **Multi-format Output**  
  Console, JSON (`--output`), or Markdown reports (`--report`).

- 🧠 **AI-Powered Fix Suggestions (Optional)**  
  Add an OpenAI API key for smart recommendations in Markdown reports.

- 🎯 **Focus on Critical Issues**  
  Use `--high-only` to trim noise.

- 🙈 **Custom Ignores**  
  Exclude files using `.vibesafeignore`, just like `.gitignore`.


## 📦 Installation

```bash
npm install -g vibesafe 
```

*(Note: Currently, for local development, use `npm link` after building)*

## 🚀 Usage

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

## 🛑📁 Ignoring Files (.vibesafeignore)

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
## 🤝 Contributing

We welcome contributions from the community!

If you have an idea for a new scanner, a bug fix, or a way to make VibeSafe better, check out our [Contributing Guide](./CONTRIBUTING.md) to get started.

Whether you're submitting a pull request or opening an issue, we appreciate your help in making security tools more developer-friendly.

## 🧾 License

VibeSafe is open source software licensed under the [MIT License](./LICENSE).

You're free to use, modify, and distribute it — even commercially — as long as the original copyright
and license are included.

For questions or commercial partnership inquiries, contact **vibesafepackage@gmail.com**.

---

## 📛 Trademark Notice

**VibeSafe™** is a trademark of Secret Society LLC.  
Use of the name “VibeSafe” for derivative tools, competing products, or commercial services is **not permitted without prior written consent.**

You are free to fork or build upon this code under the [MIT License](./LICENSE), but please use a different name and branding for public or commercial distributions.
