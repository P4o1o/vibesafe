# VibeSafe MVP Development Plan

## 1. Overview

**Problem:** Developers ship code quickly but often miss basic security checks (secrets, stale deps, known CVEs).  
**Solution:** A zero‑config CLI that scans a repo for secrets, outdated packages, and CVEs, then generates an AI‑powered risk report.  
**MVP Goal:** Enable any developer to run `vibesafe scan` and get a readable security summary—including file paths and line numbers—in under 60 s.

## 2. Personas & Use Cases

| Persona            | Scenario                                                            | Outcome                                   |
| ------------------ | ------------------------------------------------------------------- | ----------------------------------------- |
| Solo "vibe" coder  | Quickly wants to check a side‑project for exposed keys before release | Markdown/JSON report with file, location, and severity‑scored findings |
| CI/CD integrator   | Needs build to fail if any HIGH vulnerabilities are present        | CI job exits non-zero on HIGH issues      |
| Security advocate  | Reviews multiple repos for baseline security hygiene               | Exports JSON for bulk analysis            |

## 3. Scope & Non‑Goals

**In‑Scope (MVP):**  
- Secrets & plaintext key detection with file & line  
- Dependency parsing + CVE lookup  
- AI‑driven markdown risk report with fix suggestions  
- CLI UX: colorized terminal + `--output` flags  

**Out‑of‑Scope (v0.1+):**  
- Automatic patching (`--fix`)  
- Remote‑repo scanning  
- Real‑time IDE plugins  
- Telemetry collection (opt‑in only)  
- TODO: Proactively check `.gitignore` for `.env` exclusion patterns

## 4. Success Metrics

1. **Performance:** Full scan < 60 s on a 100 MB repo  
2. **Coverage:** Detects ≥ 5 unique issues in standard test repos  
3. **Adoption:** ≥ 10 installs in first week (npm/pip downloads)  
4. **Reliability:** CI exit code behavior consistent (HIGH → non-zero)

## 5. Phases & Atomic Tasks

### Phase 1: Setup & CI Integration
1. **Repo scaffold**  
   - [x] `mkdir vibesafe && cd vibesafe`  
   - [x] Initialize Git + add `.gitignore`, `LICENSE`, `README.md`  
   - [x] Choose language: TypeScript (commander.js)  
   - [x] Add basic `vibesafe scan` command stub  
2. **CI hook**  
   - [x] Write a GitHub Actions workflow that runs `vibesafe scan --high-only`  
   - [x] Ensure exit code propagates  

### Phase 2: Secrets Scanner
1. **Regex & entropy engine**  
   - [x] Define regex patterns for `.env`, AWS, JWT, SSH keys  
   - [x] Integrate an entropy checker (e.g., Shannon entropy > threshold)  
2. **File traversal**  
   - [x] Walk directory tree, skip default excludes (`node_modules`, `dist`, lockfiles, tsconfig.json, README.md)  
   - [x] Honor `.vibesafeignore` entries  
3. **Scoring & output**  
   - [x] Assign Low/Med/High severity based on pattern + entropy  
   - [x] Emit JSON record per finding including `file`, `line`, `pattern`, and `severity`  
   - [x] Added 'Info' severity for secrets in `.env` files (reduces noise)  

### Phase 3: Dependency & CVE Scanner
1. **Detect package manager**  
   - [x] Inspect files: `package.json`, `yarn.lock`, `requirements.txt`  
2. **Parse deps**  
   - [x] Extract name + version pairs  
3. **CVE lookup**  
   - [x] Call OSV.dev or NVD API with each dep  
   - [x] Capture CVE IDs, severity, published date  
4. **Threshold filtering**  
   - [x] Mark HIGH if any dep ≥ 7.0 severity  

### Phase 4: AI Risk Report
1. **Markdown skeleton**  
   - [x] Build template  
2. **LLM integration**  
   - [x] Send JSON findings + skeleton to GPT‑4o‑mini  
   - [x] Parse human‑readable summary & per‑issue suggestions  
   - [x] Merge into final MD  

### Phase 5: CLI UX & Packaging
1. **Terminal polish**  
   - [x] Colorize severities (e.g., red for High)  
   - [x] Add progress spinner during scans  
2. **Flags & outputs**  
   - [x] `--output <file.json>`  
   - [x] `--report <file.md>`  
   - [x] `--high-only` filter  
3. **Distribution**  
   - [x] Set up npm `bin` entry_point  
   - [x] Test on macOS  

### Phase 6: Additional Common Checks
1. **Insecure Default Configurations**  
   - [x] Scan config files (JSON/YAML) for flags like `DEBUG=true`, `devMode`, or permissive CORS (`*` origins)  
2. **Unvalidated File Uploads**  
   - [x] Detect code handling file uploads (e.g., multer, busboy, formidable, express-fileupload, generic patterns) without size/type restrictions  
3. **Exposed Debug/Admin Endpoints**  
   - [x] Search for routes named `/debug`, `/admin`, `/status`, `/info`, etc. using framework patterns or string literals
   - [ ] Flag those without authentication or middleware checks // (Future enhancement - complex)
4. **Lack of Rate‑Limiting**  
   - [x] Identify files with route definitions but missing `express-rate-limit` import (heuristic)
   - [ ] Flag missing throttle/retry settings in HTTP client code
   - [x] Detect missing timeout/cancellation in HTTP client calls (axios, fetch, got, request) // (Superagent check disabled due to AST complexity)
   - [ ] *TODO: Implement reliable `superagent` timeout detection via AST*
5. **Insufficient Logging & Error Sanitization**  
   - [x] Find logging of full error objects or stack traces (e.g., `console.error(err)`)
   - [ ] Detect logging of PII or sensitive data in plain text // (Future enhancement - complex)

## 6. Risks & Mitigations

- **API rate limits (OSV/NVD):** cache results locally; implement exponential back‑off  
- **False positives (secrets):** tune regex & entropy thresholds; allow exclusions  
- **LLM costs:** only call on `--report` mode; support a dry‑run without AI  

## 7. In Cursor

- **Check progress:**  
  > “What is the current status of Phase 6: Additional Common Checks?”  
- **Mark tasks done:**  
  > “Mark Insecure Default Configurations check as complete.”  

---

**Next Steps:**  
1. Tackle Phase 6 atomic tasks in order.  
2. Validate each check against representative repos.  
3. Prepare to expand into "Most Dangerous" vulnerability scans once Phase 6 is done.  
