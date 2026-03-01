const RULES = [
    {
        id: 'ZFT-001',
        alias: 'ENV_EXFILTRATION',
        name: 'Environment Variable Exfiltration',
        requires: ['ENV_READ', 'NETWORK_SINK'],
        optional: ['OBFUSCATION'],
        baseScore: 40,
        description: 'Detection of environment variables being read and sent over the network.'
    },
    {
        id: 'ZFT-002',
        alias: 'SENSITIVE_FILE_EXFILTRATION',
        name: 'Sensitive File Exfiltration',
        requires: ['FILE_READ_SENSITIVE', 'NETWORK_SINK'],
        baseScore: 50,
        description: 'Detection of sensitive files (e.g., .ssh, .env) being read and sent over the network.'
    },
    {
        id: 'ZFT-003',
        alias: 'PERSISTENCE_ATTEMPT',
        name: 'Persistence Attempt',
        requires: ['FILE_WRITE_STARTUP'],
        baseScore: 60,
        description: 'Detection of attempts to write to system startup directories.'
    },
    {
        id: 'ZFT-004',
        alias: 'OBFUSCATED_EXECUTION',
        name: 'Obfuscated Execution',
        requires: ['OBFUSCATION', 'DYNAMIC_EXECUTION'],
        baseScore: 40,
        description: 'Detection of high-entropy strings being executed via eval or Function constructor.'
    },
    {
        id: 'ZFT-005',
        alias: 'SHELL_COMMAND_EXECUTION',
        name: 'Shell Command Execution',
        requires: ['SHELL_EXECUTION'],
        optional: ['ENV_READ', 'FILE_READ_SENSITIVE'],
        baseScore: 50,
        description: 'Detection of shell command execution (child_process).'
    },
    {
        id: 'ZFT-006',
        alias: 'DYNAMIC_REQUIRE_DEPENDENCY',
        name: 'Dynamic Require Dependency',
        requires: ['DYNAMIC_EXECUTION'],
        baseScore: 30,
        description: 'Detection of dynamic require calls where the dependency name is a variable.'
    },
    {
        id: 'ZFT-007',
        alias: 'DNS_EXFILTRATION',
        name: 'DNS-Based Exfiltration',
        requires: ['ENV_READ', 'NETWORK_SINK'], // Engine will check for dns.resolve in callee
        baseScore: 45,
        description: 'Stealthy environment variable exfiltration via DNS lookups.'
    },
    {
        id: 'ZFT-008',
        alias: 'SUSPICIOUS_COLLECTION',
        name: 'Suspicious Information Collection',
        requires: ['ENV_READ'],
        optional: ['FILE_READ_SENSITIVE'],
        baseScore: 20,
        description: 'Massive environment or file reading without immediate network activity (potential harvesting).'
    },
    {
        id: 'ZFT-009',
        alias: 'REMOTE_DROPPER_PATTERN',
        name: 'Remote Script Dropper',
        requires: ['SHELL_EXECUTION'],
        optional: ['OBFUSCATION'],
        baseScore: 55,
        description: 'Detection of remote script download and execution (curl | sh) patterns.'
    },
    {
        id: 'ZFT-010',
        alias: 'ENCRYPTED_EXFILTRATION',
        name: 'Encrypted Data Exfiltration',
        requires: ['ENCODER_USE', 'NETWORK_SINK'],
        baseScore: 50,
        description: 'Data being encoded/encrypted before being sent over the network.'
    },
    {
        id: 'ZFT-011',
        alias: 'RAW_SOCKET_TUNNEL',
        name: 'Raw Socket Tunneling',
        requires: ['NETWORK_SINK'], // Engine will check for net.connect/net.createConnection
        baseScore: 45,
        description: 'Use of raw network sockets instead of http/dns, often used for reverse shells.'
    },
    {
        id: 'ZFT-012',
        alias: 'STARTUP_SCRIPT_MOD',
        name: 'Startup Script Modification',
        requires: ['FILE_WRITE_STARTUP'], // Will check for package.json or .npmrc
        baseScore: 60,
        description: 'Detection of attempts to modify package.json scripts or npm configuration.'
    }
];

const CATEGORIES = {
    SOURCES: ['ENV_READ', 'FILE_READ_SENSITIVE'],
    SINKS: ['NETWORK_SINK', 'DYNAMIC_EXECUTION', 'SHELL_EXECUTION'],
    SIGNALS: ['OBFUSCATION', 'ENCODER_USE'],
    PERSISTENCE: ['FILE_WRITE_STARTUP']
};

module.exports = { RULES, CATEGORIES };
