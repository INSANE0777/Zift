# 🛡️ Zift (v4.1.0)

[![npm version](https://img.shields.io/npm/v/@7nsane/zift.svg?style=flat-square)](https://www.npmjs.com/package/@7nsane/zift)
[![License](https://img.shields.io/npm/l/@7nsane/zift.svg?style=flat-square)](https://www.npmjs.com/package/@7nsane/zift)
[![Build Status](https://img.shields.io/badge/CI-passing-brightgreen?style=flat-square)](https://github.com/7nsane/zift)

**The Symbolically-Intelligent Ecosystem Security Engine for JavaScript.**

Zift v4.1 is the "Intelligence" release, introducing **Symbolic Taint Analysis**. It can track sensitive data through complex code transformations, destructuring, and nested object structures across module boundaries.

## 🚀 Key Advancements (v4.1.0)

- **🧠 Symbolic Taint Analysis**: Tracks data through destructuring (`const { key } = process.env`) and deep property access (`obj.a.b.c`).
- **🧬 Transformation Tracking**: Automatically follows taint through encoding methods like `Buffer.from(data).toString('base64')` or `hex`.
- **🐛 Worm & Propagation Defense**: Detects the chain of credential theft, data exfiltration, and self-publishing (registry hijacking).
- **🛡️ Deep Behavioral Hardening**: Flags wipers (recursive deletions), CI/CD secret theft, and unauthorized module/git tampering.
- **📡 OS Fingerprinting Detection**: Identifies system targeting behaviors (os.platform, arch) coupled with network activity.
- **📦 Lifecycle-Specific Intelligence**: Detects remote fetches and binary drops occurring during sensitive contexts like `preinstall`.

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
