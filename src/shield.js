const diagnostics = require('node:diagnostics_channel');

/**
 * Zift Shield Runtime Guard
 * Intercepts network and shell activity at runtime for security auditing.
 */

function setupShield() {
    console.warn('🛡️ ZIFT SHIELD ACTIVE: Monitoring suspicious runtime activity...');

    // 1. Monitor Network Activity via diagnostics_channel
    const netChannel = diagnostics.channel('net.client.socket.request.start');
    netChannel.subscribe(({ address, port }) => {
        console.warn(`[ZIFT-SHIELD] 🌐 Outbound Connection: ${address}:${port}`);
    });

    // 2. Wrap Child Process (for shell command execution)
    const cp = require('node:child_process');
    ['exec', 'spawn', 'execSync', 'spawnSync'].forEach(method => {
        const original = cp[method];
        cp[method] = function (...args) {
            const command = args[0];
            const cmdStr = typeof command === 'string' ? command : (args[1] ? args[1].join(' ') : 'unknown');
            console.warn(`[ZIFT-SHIELD] 🐚 Shell Execution: ${cmdStr}`);

            // Heuristic Check: Is it a potential dropper?
            if (cmdStr.includes('curl') || cmdStr.includes('wget') || cmdStr.includes('| sh')) {
                console.error(`[ZIFT-SHIELD] ⚠️  CRITICAL: Potential Remote Dropper detected in shell execution!`);
            }

            return original.apply(this, args);
        };
    });

    // 3. Monitor HTTP/HTTPS
    const http = require('node:http');
    const https = require('node:https');
    [http, https].forEach(mod => {
        ['request', 'get'].forEach(method => {
            const original = mod[method];
            mod[method] = function (...args) {
                let url = args[0];
                if (typeof url === 'object' && url.href) url = url.href;
                else if (typeof url === 'string') url = url;
                else url = `${args[0].host || args[0].hostname}${args[0].path || ''}`;

                console.warn(`[ZIFT-SHIELD] 📡 HTTP Request: ${url}`);
                return original.apply(this, args);
            };
        });
    });
}

// Auto-activate if required via node -r
setupShield();

module.exports = { setupShield };
