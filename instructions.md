# VibeSafe MVP Development Plan

## 1. Overview

**Problem:** Developers ship code quickly but often miss basic security checks (secrets, stale deps, known CVEs).  
**Solution:** A zero‑config CLI that scans a repo for secrets, outdated packages, and CVEs, then generates an AI‑powered risk report.  
**MVP Goal:** Enable any developer to run `vibesafe scan` and get a readable security summary—including file paths and line numbers—in under 60 s.

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

1. **Performance:** Full scan < 60 s on a 100 MB repo  
2. **Coverage:** Detects ≥ 5 unique issues in standard test repos  
3. **Adoption:** ≥ 10 installs in first week (npm/pip downloads)  
4. **Reliability:** CI exit code behavior consistent (HIGH → non-zero)

## 5. Phases & Atomic Tasks

### Phase 1: Setup & CI Integration
1. **Repo scaffold**  
   - [x] `mkdir vibesafe && cd vibesafe`  
   - [x] Initialize Git + add `.gitignore`, `LICENSE`, `README.md`  
   - [x] Choose language: TypeScript (commander.js) ~~_or_ Python (argparse)~~  
   - [x] Add basic `vibesafe scan` command stub  
2. **CI hook**  
   - [x] Write a GitHub Actions workflow that runs `vibesafe scan --high-only`  
   - [x] Ensure exit code propagates  

### Phase 2: Secrets Scanner
1. **Regex & entropy engine**  
   - [x] Define regex patterns for `.env`, AWS, JWT, SSH keys
   - [x] Integrate an entropy checker (e.g., Shannon entropy > threshold)
2. **File traversal**  
   - [x] Walk directory tree, skip default excludes (`node_modules`, `dist`)
   - [x] Honor `.vibesafeignore` entries
3. **Scoring & output**  
   - [x] Assign Low/Med/High severity based on pattern + entropy
   - [x] Emit JSON record per finding including `file`, `line`, `pattern`, and `severity`  

### Phase 3: Dependency & CVE Scanner
1. **Detect package manager**  
   - [x] Inspect files: `package.json`, `yarn.lock`, `requirements.txt`  
2. **Parse deps**  
   - [x] Extract name + version pairs  
3. **CVE lookup**  
   - [x] Call OSV.dev or NVD API with each dep  
   - [x] Capture CVE IDs, severity, published date  
4. **Threshold filtering**  
   - [x] Mark HIGH if any dep ≥ 7.0 severity  

### Phase 4: AI Risk Report
1. **Markdown skeleton**  
   - [x] Build template:
     ```md
     # VibeSafe Report

     ## Summary
     - Total Issues: 5 (2 High, 2 Medium, 1 Low)

     ## Details
     | File               | Location   | Issue            | Severity | CVE/Pattern   |
     | ------------------ | ---------- | ---------------- | -------- | ------------- |
     | `.env`             | line 10    | AWS Key exposed  | High     | —             |
     | `config/app.js`    | line 45    | JWT secret       | Medium   | —             |
     | `package.json`     | line 23    | lodash 4.17      | Medium   | CVE-2024-123  |
     | `requirements.txt` | line 12    | Django 2.2       | High     | CVE-2023-456  |
     | `src/utils.ts`     | line 80    | Hardcoded token  | Low      | —             |

     ## Fix Suggestions
     1. Remove AWS keys from code; use environment variables and a secrets vault.  
     2. Rotate JWT secret and move to env vars.  
     3. Upgrade `lodash` to ≥ 4.17.21.  
     4. Update Django to ≥ 3.2.  
     5. Replace hardcoded tokens with secure storage.
     ```
2. **LLM integration**  
   - [x] Send JSON findings + skeleton to GPT‑4o-mini  
   - [x] Parse human‑readable summary & per‑issue suggestions  
   - [x] Merge into final MD  

### Phase 5: CLI UX & Packaging
1. **Terminal polish**  
   - [ ] Colorize severities (e.g., red for High)  
   - [ ] Add progress spinner during scans  
2. **Flags & outputs**  
   - [ ] `--output <file.md|.json>`  
   - [ ] `--high-only` filter  
3. **Distribution**  
   - [ ] Set up npm `bin` or Python `entry_point`  
   - [ ] Test on macOS, Win, Linux  

## 6. Timeline & Ownership

| Week   | Focus                          | Owner        |
| ------ | ------------------------------ | ------------ |
| Week 1 | Phase 1 scaffold + CI          | @you         |
| Week 2 | Phase 2 secrets scanner        | @security    |
| Week 3 | Phase 3 dep & CVE scanner      | @sec‑lead    |
| Week 4 | Phase 4 AI report & polish     | @AI‑engineer |
| Week 5 | Phase 5 packaging & QA         | @release     |

## 7. Risks & Mitigations

- **API rate limits (OSV/NVD):** cache results locally; implement exponential back‑off  
- **False positives (secrets):** tune regex & entropy thresholds; allow exclusions  
- **LLM costs:** only call on `--report` mode; support a dry‑run without AI  

## 8. In Cursor

- **Check progress:**  
  > “What is the current status of Phase 2: Secrets Scanner?”  
- **Mark tasks done:**  
  > “Mark Phase 3.3 (CVE lookup) as complete.”  

---

**Next Steps:**  
1. Review personas & success metrics.  
2. Assign owners & adjust timeline as needed.  
3. Kick off Week 1!  
