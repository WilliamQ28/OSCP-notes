# 🧠 OSCP Note-Taking Strategy

## 🔒 Purpose of Note-Taking

- Ensure repeatability of test results.
- Track exactly what was done (commands, actions, findings).
- Support professional, clear reporting after engagements.
- Maintain portable, offline-compatible documentation (especially for exam use).

---

## 🧰 Tooling & Format

### Recommended Editors
- Obsidian (local markdown)
- Sublime Text / VSCode with markdown preview
- CherryTree (on Kali)

### Screenshots: Good vs Bad

**Good screenshots:**
- One concept at a time.
- Clear framing, relevant material only.
- Supports description directly in the notes.

**Bad screenshots:**
- Illegible or zoomed out.
- Irrelevant UI or obfuscated details.
- Lacking context or support.

### General Note Format
- Every command, GUI action, or modification must be recorded.
- Use proper markdown code blocks for commands and payloads.
- Reference CVEs and document PoC payloads.
- Include preconditions and exact steps.

---

## 🗂️ Directory & File Structure

```
oscp-notes/
├── recon/
│   ├── nmap.md
│   └── enum.md
├── privesc/
│   ├── linux.md
│   └── windows.md
├── web/
│   ├── sqli.md
│   └── xss.md
├── exploits/
│   ├── file-upload.md
│   └── msfvenom.md
├── reporting/
│   └── templates/
└── screenshots/
```

---

## 📝 Reporting Guidelines

### Executive Summary
- **Scope**: Describe tested targets and constraints.
- **Timeframe**: Provide date and duration of testing.
- **Methodology**: State the framework used (e.g., OWASP PTES).
- **Limitations**: E.g., no accounts provided, black-box test.

### Example:
```
The client hired OffSec to test their https://kali.org/login web application
from Jan 3-5, 2025, using OWASP methodology. No test accounts were provided.
Testing was black-box from an external IP, during working hours.
```

### Positive Observations
- Strong filtering prevented malicious uploads.
- Lockout policies stopped brute-force attempts.
- Strong password policy in place.

### Vulnerabilities Summary (Example)
- **Issue**: Stored XSS via comment form.
- **Impact**: Arbitrary JavaScript execution in victim’s browser.
- **Fix**: Sanitize user input and suppress verbose errors.

---

## 🛠️ Technical Findings Table

| Ref | Severity | Area                  | Issue                      | Recommendation                |
|-----|----------|------------------------|-----------------------------|-------------------------------|
| F1  | High     | Input Validation       | Stored XSS in comment form | Implement proper sanitization |
| F2  | Medium   | Patch Management       | Outdated Apache version    | Apply OS and service patches  |
| F3  | Low      | Server Misconfiguration| Directory listing enabled  | Disable auto-indexing         |

---

## 📌 When No Vulnerabilities Found

If no issues exist, state clearly and simply, e.g.:
> “The application was thoroughly tested and no vulnerabilities were found. All user inputs were properly sanitized and no unsafe error disclosures were present.”

---

## 📎 Appendices

- Additional references and CVEs.
- Extended technical logs.
- Out-of-scope but related findings.
