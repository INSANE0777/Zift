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
    }
];

const CATEGORIES = {
    SOURCES: ['ENV_READ', 'FILE_READ_SENSITIVE', 'MASS_ENV_ACCESS'],
    SINKS: ['NETWORK_SINK', 'DNS_SINK', 'RAW_SOCKET_SINK', 'DYNAMIC_EXECUTION', 'SHELL_EXECUTION', 'DYNAMIC_REQUIRE'],
    SIGNALS: ['OBFUSCATION', 'ENCODER_USE', 'REMOTE_FETCH_SIGNAL', 'PIPE_TO_SHELL_SIGNAL', 'NATIVE_BINARY_DETECTED', 'OPAQUE_STRING_SKIP', 'NON_DETERMINISTIC_SINK'],
    PERSISTENCE: ['FILE_WRITE_STARTUP'],
    CONTEXT: ['LIFECYCLE_CONTEXT']
};

module.exports = { RULES, CATEGORIES };
