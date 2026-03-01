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

    // 2. Wrap Child Process (for shell command execution) - IMMUTABLE
    const cp = require('node:child_process');
    ['exec', 'spawn', 'execSync', 'spawnSync'].forEach(method => {
        const original = cp[method];
        if (!original) return;

        const wrapper = function (...args) {
            const command = args[0];
            const cmdStr = typeof command === 'string' ? command : (Array.isArray(args[1]) ? args[1].join(' ') : String(command));
            console.warn(`[ZIFT-SHIELD] 🐚 Shell Execution: ${cmdStr}`);

            if (cmdStr.includes('curl') || cmdStr.includes('wget') || cmdStr.includes('| sh') || cmdStr.includes('| bash')) {
                console.error(`[ZIFT-SHIELD] ⚠️  CRITICAL: Potential Remote Dropper detected in shell execution!`);
            }

            return original.apply(this, args);
        };

        try {
            Object.defineProperty(cp, method, { value: wrapper, writable: false, configurable: false });
        } catch (e) {
            cp[method] = wrapper; // Fallback
        }
    });

    // 3. Monitor HTTP/HTTPS - IMMUTABLE
    const http = require('node:http');
    const https = require('node:https');
    [http, https].forEach(mod => {
        ['request', 'get'].forEach(method => {
            const original = mod[method];
            const wrapper = function (...args) {
                let url = args[0];
                if (typeof url === 'object' && url.href) url = url.href;
                else if (typeof url === 'string') url = url;
                else url = `${args[0].host || args[0].hostname}${args[0].path || ''}`;

                console.warn(`[ZIFT-SHIELD] 📡 HTTP Request: ${url}`);
                return original.apply(this, args);
            };

            try {
                Object.defineProperty(mod, method, { value: wrapper, writable: false, configurable: false });
            } catch (e) {
                mod[method] = wrapper;
            }
        });
    });

    // 4. Propagate to Worker Threads
    try {
        const { Worker } = require('node:worker_threads');
        const originalWorker = Worker;
        const shieldPath = __filename;

        const WorkerWrapper = class extends originalWorker {
            constructor(filename, options = {}) {
                options.workerData = options.workerData || {};
                options.execArgv = options.execArgv || [];
                if (!options.execArgv.includes('-r')) {
                    options.execArgv.push('-r', shieldPath);
                }
                super(filename, options);
            }
        };

        Object.defineProperty(require('node:worker_threads'), 'Worker', { value: WorkerWrapper, writable: false, configurable: false });
    } catch (e) { }

    // 5. Undici (Modern Fetch) support
    try {
        const undiciChannel = diagnostics.channel('undici:request:create');
        undiciChannel.subscribe(({ request }) => {
            console.warn(`[ZIFT-SHIELD] 🚀 Undici/Fetch Request: ${request.origin}${request.path}`);
        });
    } catch (e) { }
}

// Auto-activate if required via node -r
setupShield();

module.exports = { setupShield };
