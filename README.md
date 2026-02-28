# Zift 🛡️

**Zift** is an elite, high-performance security scanner designed to detect suspicious patterns in npm packages before they are executed. By using deterministic AST analysis and lightweight variable propagation, Zift identifies potential credential exfiltration, malicious persistence, and obfuscated execution with extreme precision.

## Key Features

- **Rule-Based Scoring**: Deterministic classification (Critical, High, Medium, Low) using professional Rule IDs (e.g., `ZFT-001`).
- **Context-Aware Detection**: Multiplier applied for suspicious activity found in lifecycle scripts (e.g., `postinstall`).
- **Data-Flow Tracking**: Lightweight variable propagation to detect process.env exfiltration.
- **Obfuscation Detection**: Shannon entropy-based identification of high-entropy strings combined with dynamic execution.
- **High Performance**: Optimized AST traversal with file size caps (512KB) and skip patterns for non-source files.

## Installation

```bash
npm install -g zift
```

## Usage

```bash
# Scan current directory
zift .

# Scan a specific package or directory
zift ./node_modules/example-pkg

# Output result in JSON format for CI/CD pipelines
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

## Limitations

Transparency is key to trust. As a V1 static analysis tool, Zift has the following scope boundaries:

- **No Interprocedural Flow**: Variable tracking is restricted to function scope; it does not track data across function boundaries.
- **No Cross-File Propagation**: Analysis is performed on a per-file basis.
- **No Dynamic Runtime Analysis**: Zift does not execute code; it cannot detect evasion techniques that only trigger during execution (e.g., sophisticated sandbox escapes).
- **Heuristic Entropy**: Entropy calculation is a signal, not a guarantee. Bundled assets may trigger medium-level warnings.

## Performance Guarantees

- **File Cap**: Files larger than **512KB** are skipped to ensure predictable scan times.
- **String Cap**: Entropy calculation is skipped for literal strings longer than **2048 characters**.

---
Built for the security-conscious developer.
