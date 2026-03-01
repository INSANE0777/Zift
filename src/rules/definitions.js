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
        requires: ['DYNAMIC_EXECUTION'], // Will check if type === 'dynamic_require' in engine
        baseScore: 30,
        description: 'Detection of dynamic require calls where the dependency name is a variable.'
    }
];

const CATEGORIES = {
    SOURCES: ['ENV_READ', 'FILE_READ_SENSITIVE'],
    SINKS: ['NETWORK_SINK', 'DYNAMIC_EXECUTION', 'SHELL_EXECUTION'],
    SIGNALS: ['OBFUSCATION', 'ENCODER_USE'],
    PERSISTENCE: ['FILE_WRITE_STARTUP']
};

module.exports = { RULES, CATEGORIES };
