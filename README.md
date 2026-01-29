# 🚜 Groundskeeper Willie: The Angriest Code Auditor

"Zero Trust. Zero Politeness. Zero Grease."

Groundskeeper Willie is a brutal security and optimization auditor that finds the "grease" in your code and scrubs it clean. Unlike polite AI assistants, Willie doesn't care about your feelings—he only cares about your code quality.

## 🚀 Capabilities

### 🔍 Security Auditing

Willie hunts for vulnerabilities across multiple languages:

- **Python**: Insecure imports, dangerous `exec`/`eval`, and hardcoded secrets.
- **JavaScript/TypeScript**: DOM-based XSS, insecure storage, and prototype pollution.
- **Solidity**: Reentrancy risks, integer overflows, and access control issues.
- **Rust**: Unsafe blocks, potential panics, and memory mismanagement.

### 🏗️ Infrastructure & DevOps (NEW)

Audit your configurations before they leak your secrets:

- **Database Security**: Detects hardcoded connection strings and insecure local configs.
- **Port Auditing**: Flags sensitive services (MySQL, Redis, FTP) exposed on public ports.
- **Environment health**: Ensures essential variables (`SECRET_KEY`, `NODE_ENV`) are present and safe.

### 🌐 Web Optimization (NEW)

Don't let bloated frontend code slow you down:

- **Image Formats**: Willie flags heavy JPG/PNG files and suggests WebP/AVIF.
- **HTML Health**: Catches missing `alt` tags and deprecated elements.
- **CSS Redundancy**: Identifies duplicate selectors and `!important` abuse.

## 🛠️ Commands

### `scan`

Audit a directory or file without making changes.

```bash
willie scan ./src
```

### `fix`

Apply safe auto-fixes and let Willie leave some helpful(?) comments.

```bash
willie fix .
```

### `scrub`

The ultimate cleanup. Willie runs scan/fix cycles until your code is 100% clean or he gives up in disgust.

```bash
willie scrub .
```

---
> *"If it's not Scottish, it's CRAP!"* - Willie
> *(Last Updated: Jan 29 2026)*
