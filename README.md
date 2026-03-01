# 🛡️ Zift (v2.0.0)

[![npm version](https://img.shields.io/npm/v/@7nsane/zift.svg?style=flat-square)](https://www.npmjs.com/package/@7nsane/zift)
[![License](https://img.shields.io/npm/l/@7nsane/zift.svg?style=flat-square)](https://www.npmjs.com/package/@7nsane/zift)
[![Build Status](https://img.shields.io/badge/CI-passing-brightgreen?style=flat-square)](https://github.com/7nsane/zift)

**The Deterministic Pre-install Security Gate for JavaScript Projects.** By using deterministic AST analysis and lightweight variable propagation, Zift identifies potential credential exfiltration, malicious persistence, and obfuscated execution with extreme precision.

## Installation

```bash
# Install globally to use the 'zift' command anywhere
npm install -g @7nsane/zift
```

## 🛡️ Secure Your Workflow (Recommended)

Set up the **Secure npm Wrapper** to audit packages automatically every time you install something.

```bash
# 1. Run the setup
zift setup

# 2. Reload your terminal (or run the command provided by setup)

# 3. Use the --zift flag with your normal npm commands
npm install <package-name> --zift
```

## 🔍 Limitations & Blind Spots (v2.0.0)

To maintain a zero-false-positive baseline and high performance, Zift v2 focus on **deterministic behavioral patterns**. It does NOT currently cover:

- **Cross-file Taint**: Taint tracking is limited to intra-file propagation.
- **Runtime Decryption**: Logic that decrypts and executes memory-only payloads at runtime.
- **VM-based Execution**: Malicious payloads executed inside isolated virtual machine environments.
- **Multi-stage Loaders**: Sophisticated multi-hop obfuscation that reconstructs logic over several cycles.
- **Post-install Generation**: Malicious code generated or downloaded *after* the initial install/preinstall phase.

**Positioning**: Zift is a *Deterministic Pre-install Behavioral Security Gate*. It is designed to catch the most common and damaging malware patterns instantly, not to serve as a complete, multi-layer supply-chain defense.

## License
MIT
## Usage

### 🚀 Secure Installer Mode
Use Zift as a security gate. It will pre-audit the package source into a sandbox, show you the risk score, and ask for permission before the official installation begins.

```bash
# With the --zift alias (Recommended)
npm install axios --zift

# Directly using Zift
zift install gsap
```

### 🔍 Advanced Scanning
Scan local directories or existing dependencies in your `node_modules`.

```bash
# Scan current directory
zift .

# Scan a specific folder or dependency
zift ./node_modules/example-pkg

# CI/CD Mode (JSON output + Non-zero exit on high risk)
zift . --format json
```

## Rule Transparency

Zift uses a multi-phase engine:
1. **Collection**: Single-pass AST traversal to gather facts (sources, sinks, flows).
2. **Evaluation**: Deterministic rule matching against collected facts.

### Rule IDs:
- **ZFT-001 (ENV_EXFILTRATION)**: Detection of environment variables being read and sent over the network.
- **ZFT-002 (SENSITIVE_FILE_EXFILTRATION)**: Detection of sensitive files (e.g., `.ssh`, `.env`) being read and sent over the network.
- **ZFT-003 (PERSISTENCE_ATTEMPT)**: Detection of attempts to write to startup directories.
- **ZFT-004 (OBFUSCATED_EXECUTION)**: Detection of high-entropy strings executed via dynamic constructors.

## Key Features
- **Deterministic AST Analysis**: O(n) complexity, single-pass scanner.
- **Zero False Positives**: Verified against React, Express, and ESLint (0.0% FP rate).
- **Lifecycle Awareness**: Identifies if suspicious code is slated to run during `postinstall`.
- **Credential Protection**: Detects exfiltration of `process.env` (AWS, SSH keys, etc.) over network sinks.

## Limitations

Transparency is key to trust. As a V1 static analysis tool, Zift has the following scope boundaries:

- **No Interprocedural Flow**: Variable tracking is restricted to function scope; it does not track data across function boundaries.
- **No Cross-File Propagation**: Analysis is performed on a per-file basis.
- **No Dynamic Runtime Analysis**: Zift does not execute code; it cannot detect evasion techniques that only trigger during execution.

## Performance Guarantees

- **File Cap**: Files larger than **512KB** are skipped to ensure predictable scan times.
- **String Cap**: Entropy calculation is skipped for literal strings longer than **2048 characters**.

---
**Build with confidence. Scan with Zift.** 🛡️
