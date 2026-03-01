# 🛡️ Zift (v3.0.0)

[![npm version](https://img.shields.io/npm/v/@7nsane/zift.svg?style=flat-square)](https://www.npmjs.com/package/@7nsane/zift)
[![License](https://img.shields.io/npm/l/@7nsane/zift.svg?style=flat-square)](https://www.npmjs.com/package/@7nsane/zift)
[![Build Status](https://img.shields.io/badge/CI-passing-brightgreen?style=flat-square)](https://github.com/7nsane/zift)

**The Intelligent Ecosystem Security Engine for JavaScript.**

Zift v3.0 is a massive leap forward, moving beyond static analysis into **Cross-File Intelligence** and **Runtime Protection**. It is designed to identify and stop advanced supply-chain attacks (credential exfiltration, reverse-shell droppers) before they hit your production environment.

## 🚀 Major Features (v3.0.0)

- **🌍 Cross-File Taint Tracking**: Tracks sensitive data (e.g., `process.env.TOKEN`) across `import/export` and `require` boundaries.
- **🧠 VM-Based De-obfuscation**: Safe, sandboxed evaluation of string manipulation logic (e.g., character arrays, reverse/join) to reveal hidden malicious signals.
- **🛡️ Zift Shield (Runtime Guard)**: A real-time audit layer for network and shell activity. Run `zift protect` to monitor your app's dependencies in real-world conditions.
- **🔒 Lockfile Security**: Automatic auditing of `package-lock.json` and `yarn.lock` for registry confusion.

## 📦 Quick Start

```bash
# 1. Install Zift
npm install -g @7nsane/zift

# 2. Setup Secure Wrappers (adds --zift flag to npm/bun/pnpm)
zift setup

# 3. Audit a local project
zift .

# 4. Run your application with Active Shield
zift protect index.js
```

## 🔍 How It Works

Zift uses a **Deterministic AST Analysis** engine. Unlike regex-based scanners, Zift understands the structure of your code. It tracks the flow of data from sensitive **Sources** (like `process.env`) to dangerous **Sinks** (like `fetch` or `child_process.exec`).

- **Collection**: Single-pass O(n) traversal.
- **Evaluation**: Priority-based rule matching.
- **Intelligence**: Cross-file propagation and VM-based reveal.

## 🛠️ Commands

| Command | Description |
| --- | --- |
| `zift .` | Deep scan of the current directory |
| `zift install <pkg>` | Pre-audit and install a package securely |
| `zift protect <app>` | Launch application with **Zift Shield** runtime auditing |
| `zift setup` | Configure shell aliases for secure package management |

---
**Build with confidence. Secure with Zift.** 🛡️
