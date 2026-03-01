# 🛡️ Zift (v4.0.0)

[![npm version](https://img.shields.io/npm/v/@7nsane/zift.svg?style=flat-square)](https://www.npmjs.com/package/@7nsane/zift)
[![License](https://img.shields.io/npm/l/@7nsane/zift.svg?style=flat-square)](https://www.npmjs.com/package/@7nsane/zift)
[![Build Status](https://img.shields.io/badge/CI-passing-brightgreen?style=flat-square)](https://github.com/7nsane/zift)

**The Deeply Hardened Ecosystem Security Engine for JavaScript.**

Zift v4.0 is the "Deep Hardening" release, featuring **Immutable Runtime Guards** and **Opaque Payload Detection**, specifically designed to resist active attacker bypasses.

## 🚀 Key Advancements (v4.0.0)

- **🛡️ Immutable Zift Shield**: Runtime sinks (`http`, `child_process`) are now immutable. Attackers cannot delete or re-assign them to bypass protection.
- **🧩 Opaque Payload Detection**: Automatically flags compiled native binaries (`.node`) as high-risk.
- **🧵 Universal Protection**: Zift Shield now automatically propagates into `worker_threads`.
- **🕵️ Evasion Tracking**: Detects non-deterministic sink construction (e.g., using `Date.now()` or `Math.random()` to hide strings).
- **🌍 Cross-File Intelligence**: Full multi-pass taint tracking for ESM and CommonJS.

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
