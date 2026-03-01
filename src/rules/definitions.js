const RULES = [
    {
        id: 'ZFT-001',
        alias: 'ENV_EXFILTRATION',
        name: 'Environment Variable Exfiltration',
        requires: ['ENV_READ', 'NETWORK_SINK'],
        optional: ['OBFUSCATION'],
        priority: 1,
        baseScore: 40,
        description: 'Detection of environment variables being read and sent over the network.'
    },
    {
        id: 'ZFT-002',
        alias: 'SENSITIVE_FILE_EXFILTRATION',
        name: 'Sensitive File Exfiltration',
        requires: ['FILE_READ_SENSITIVE', 'NETWORK_SINK'],
        priority: 1,
        baseScore: 50,
        description: 'Detection of sensitive files (e.g., .ssh, .env) being read and sent over the network.'
    },
    {
        id: 'ZFT-003',
        alias: 'PERSISTENCE_ATTEMPT',
        name: 'Persistence Attempt',
        requires: ['FILE_WRITE_STARTUP'],
        priority: 2,
        baseScore: 60,
        description: 'Detection of attempts to write to system startup directories.'
    },
    {
        id: 'ZFT-004',
        alias: 'OBFUSCATED_EXECUTION',
        name: 'Obfuscated Execution',
        requires: ['OBFUSCATION', 'DYNAMIC_EXECUTION'],
        priority: 2,
        baseScore: 40,
        description: 'Detection of high-entropy strings being executed via eval or Function constructor.'
    },
    {
        id: 'ZFT-005',
        alias: 'SHELL_COMMAND_EXECUTION',
        name: 'Shell Command Execution',
        requires: ['SHELL_EXECUTION'],
        optional: ['ENV_READ', 'FILE_READ_SENSITIVE'],
        priority: 1,
        baseScore: 50,
        description: 'Detection of shell command execution (child_process).'
    },
    {
        id: 'ZFT-006',
        alias: 'DYNAMIC_REQUIRE_DEPENDENCY',
        name: 'Dynamic Require Dependency',
        requires: ['DYNAMIC_REQUIRE'],
        priority: 1,
        baseScore: 30,
        description: 'Detection of dynamic require calls where the dependency name is a variable.'
    },
    {
        id: 'ZFT-007',
        alias: 'DNS_EXFILTRATION',
        name: 'DNS-Based Exfiltration',
        requires: ['ENV_READ', 'DNS_SINK'],
        priority: 2,
        baseScore: 45,
        description: 'Stealthy environment variable exfiltration via DNS lookups.'
    },
    {
        id: 'ZFT-008',
        alias: 'SUSPICIOUS_COLLECTION',
        name: 'Suspicious Information Collection',
        requires: ['MASS_ENV_ACCESS'],
        optional: ['FILE_READ_SENSITIVE'],
        priority: 1,
        baseScore: 20,
        description: 'Massive environment reading without immediate network activity (potential harvesting).'
    },
    {
        id: 'ZFT-009',
        alias: 'REMOTE_DROPPER_PATTERN',
        name: 'Remote Script Dropper',
        requires: ['SHELL_EXECUTION', 'REMOTE_FETCH_SIGNAL'],
        optional: ['OBFUSCATION', 'PIPE_TO_SHELL_SIGNAL'],
        priority: 3,
        baseScore: 55,
        description: 'Detection of remote script download and execution (curl | sh) patterns.'
    },
    {
        id: 'ZFT-010',
        alias: 'ENCODED_EXFILTRATION',
        name: 'Encoded Data Exfiltration',
        requires: ['ENV_READ', 'NETWORK_SINK', 'ENCODER_USE'],
        priority: 3,
        baseScore: 70,
        description: 'Sensitive data encoded before transmission to evade detection.'
    },
    {
        id: 'ZFT-011',
        alias: 'RAW_SOCKET_TUNNEL',
        name: 'Raw Socket Tunneling',
        requires: ['RAW_SOCKET_SINK'],
        priority: 2,
        baseScore: 45,
        description: 'Use of raw network sockets instead of http/dns, often used for reverse shells.'
    },
    {
        id: 'ZFT-012',
        alias: 'STARTUP_SCRIPT_MOD',
        name: 'Startup Script Modification',
        requires: ['FILE_WRITE_STARTUP'],
        priority: 2,
        baseScore: 60,
        description: 'Detection of attempts to modify package.json scripts or npm configuration.'
    },
    {
        id: 'ZFT-013',
        alias: 'OPAQUE_BINARY_PAYLOAD',
        name: 'Opaque Binary Payload',
        requires: ['NATIVE_BINARY_DETECTED'],
        priority: 2,
        baseScore: 40,
        description: 'Detection of compiled native binaries (.node) which are opaque to static analysis.'
    },
    {
        id: 'ZFT-014',
        alias: 'EVASIVE_SINK_CONSTRUCTION',
        name: 'Evasive Sink Construction',
        requires: ['NON_DETERMINISTIC_SINK'],
        priority: 3,
        baseScore: 50,
        description: 'Detection of dangerous sinks using non-deterministic construction (Date.now, Math.random) to evade analysis.'
    },
    {
        id: 'ZFT-015',
        alias: 'HIGH_ENTROPY_OPAQUE_STRING',
        name: 'High Entropy Opaque String',
        requires: ['OPAQUE_STRING_SKIP'],
        priority: 1,
        baseScore: 25,
        description: 'Detection of very large high-entropy strings that exceed scanning limits.'
    },
    {
        id: 'ZFT-016',
        alias: 'CREDENTIAL_STEAL_ATTEMPT',
        name: 'Credential Theft Attempt',
        requires: ['CREDENTIAL_FILE_ACCESS', 'NETWORK_SINK'],
        priority: 1,
        baseScore: 85,
        description: 'Detection of access to sensitive credential files (.aws, .ssh, .npmrc) and exfiltration.'
    },
    {
        id: 'ZFT-017',
        alias: 'ANTI_ANALYSIS_EVASION',
        name: 'Anti-Analysis / Evasion',
        requires: ['EVASION_ENVIRONMENT_CHECK'],
        optional: ['DYNAMIC_EXECUTION'],
        priority: 2,
        baseScore: 50,
        description: 'Detection of code that checks for VM, Debugger, or Sandbox environments to evade analysis.'
    },
    {
        id: 'ZFT-018',
        alias: 'CRYPTO_WALLET_DRAINER',
        name: 'Crypto-Wallet Drainer Hook',
        requires: ['WALLET_HOOK'],
        priority: 1,
        baseScore: 95,
        description: 'Detection of hooks on browser-based crypto wallets (window.ethereum, Solana).'
    },
    {
        id: 'ZFT-019',
        alias: 'DISCORD_TOKEN_STEALER',
        name: 'Discord Token Stealer',
        requires: ['DISCORD_STORAGE_ACCESS', 'NETWORK_SINK'],
        priority: 1,
        baseScore: 80,
        description: 'Detection of Discord local storage access followed by network activity.'
    },
    {
        id: 'ZFT-020',
        alias: 'HIGH_RISK_WEBHOOK_SINK',
        name: 'High-Risk Webhook Exfiltration',
        requires: ['WEBHOOK_SINK'],
        optional: ['ENV_READ', 'ENCODER_USE'],
        priority: 2,
        baseScore: 60,
        description: 'Detection of data being sent to known high-risk exfiltration domains (Discord Webhooks, Pipedream).'
    },
    {
        id: 'ZFT-021',
        alias: 'WIPER_MODULE_DETECTED',
        name: 'Destructive Wiper Module',
        requires: ['WIPER_OPERATION'],
        priority: 1,
        baseScore: 100,
        description: 'Detection of recursive deletion operations on sensitive directory structures (Home, Root, Documents).'
    },
    {
        id: 'ZFT-022',
        alias: 'CICD_SECRET_EXFILTRATION',
        name: 'CI/CD Secret Exfiltration',
        requires: ['CICD_SECRET_ACCESS', 'NETWORK_SINK'],
        priority: 1,
        baseScore: 90,
        description: 'Detection of CI/CD secrets (GITHUB_TOKEN, CIRCLECI_TOKEN) being accessed and exfiltrated.'
    },
    {
        id: 'ZFT-023',
        alias: 'REGISTRY_POISONING_ATTEMPT',
        name: 'Registry Poisoning Attempt',
        requires: ['REGISTRY_TAMPER'],
        priority: 2,
        baseScore: 70,
        description: 'Detection of unauthorized modifications to .npmrc or registry configuration.'
    },
    {
        id: 'ZFT-024',
        alias: 'MODULE_REPOS_HIJACKING',
        name: 'Module/Repository Hijacking',
        requires: ['MODULE_TAMPER'],
        priority: 2,
        baseScore: 75,
        description: 'Detection of unauthorized write operations into node_modules or .git directories.'
    },
    {
        id: 'ZFT-025',
        alias: 'REVERSE_SHELL_PATTERN',
        name: 'Reverse Shell Behavior',
        requires: ['REVERSE_SHELL_BEHAVIOR'],
        priority: 1,
        baseScore: 95,
        description: 'Detection of network sockets being piped directly into system shells (Reverse Shell pattern).'
    },
    {
        id: 'ZFT-026',
        alias: 'REGISTRY_PUBLISH_ATTEMPT',
        name: 'Registry Publication Attempt',
        requires: ['PUBLISH_SINK'],
        priority: 1,
        baseScore: 85,
        description: 'Detection of attempts to run npm publish or interact with registry upload APIs (Worm behavior).'
    },
    {
        id: 'ZFT-027',
        alias: 'FINGERPRINT_OS_TARGETING',
        name: 'OS Fingerprinting & Targeting',
        requires: ['FINGERPRINT_SIGNAL'],
        optional: ['NETWORK_SINK', 'SHELL_EXECUTION'],
        priority: 2,
        baseScore: 55,
        description: 'Detection of OS metadata collection (platform, release, arch) potentially for targeted payload delivery.'
    },
    {
        id: 'ZFT-028',
        alias: 'WORM_PROPAGATION_CHAIN',
        name: 'Automated Worm Propagation',
        requires: ['CREDENTIAL_FILE_ACCESS', 'NETWORK_SINK', 'PUBLISH_SINK'],
        priority: 1,
        baseScore: 100,
        description: 'Detection of the full worm cycle: Harvest tokens -> Exfiltrate -> Self-publish.'
    },
    {
        id: 'ZFT-029',
        alias: 'LIFECYCLE_BINARY_FETCH',
        name: 'Lifecycle Binary Drop',
        requires: ['REMOTE_FETCH_SIGNAL', 'LIFECYCLE_CONTEXT'],
        optional: ['SHELL_EXECUTION'],
        priority: 1,
        baseScore: 90,
        description: 'Detection of remote payload fetching specifically during package install/lifecycle scripts.'
    }
];

const CATEGORIES = {
    SOURCES: ['ENV_READ', 'FILE_READ_SENSITIVE', 'MASS_ENV_ACCESS', 'CREDENTIAL_FILE_ACCESS', 'DISCORD_STORAGE_ACCESS', 'CICD_SECRET_ACCESS'],
    SINKS: ['NETWORK_SINK', 'DNS_SINK', 'RAW_SOCKET_SINK', 'DYNAMIC_EXECUTION', 'SHELL_EXECUTION', 'DYNAMIC_REQUIRE', 'WEBHOOK_SINK', 'WIPER_OPERATION', 'REGISTRY_TAMPER', 'MODULE_TAMPER', 'REVERSE_SHELL_BEHAVIOR', 'PUBLISH_SINK'],
    SIGNALS: ['OBFUSCATION', 'ENCODER_USE', 'REMOTE_FETCH_SIGNAL', 'PIPE_TO_SHELL_SIGNAL', 'NATIVE_BINARY_DETECTED', 'OPAQUE_STRING_SKIP', 'NON_DETERMINISTIC_SINK', 'EVASION_ENVIRONMENT_CHECK', 'WALLET_HOOK', 'FINGERPRINT_SIGNAL'],
    PERSISTENCE: ['FILE_WRITE_STARTUP'],
    CONTEXT: ['LIFECYCLE_CONTEXT']
};

module.exports = { RULES, CATEGORIES };
