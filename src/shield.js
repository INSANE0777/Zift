const diagnostics = require('node:diagnostics_channel');

/**
 * Zift Shield Runtime Guard
 * Intercepts network and shell activity at runtime for security auditing.
 */

function setupShield() {
    let manifest = null;
    try {
        const path = require('node:path');
        const fs = require('node:fs');
        const manifestPath = path.join(process.cwd(), 'zift.json');
        if (fs.existsSync(manifestPath)) {
            manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
            console.warn(`[ZIFT-SHIELD] 📜 Zero-Trust Manifest Loaded: ${manifest.name}@${manifest.version}`);
        }
    } catch (e) {
        console.error('[ZIFT-SHIELD] ⚠️ Error loading manifest:', e.message);
    }

    // 1. Monitor Network Activity via diagnostics_channel
    const netChannel = diagnostics.channel('net.client.socket.request.start');
    netChannel.subscribe(({ address, port }) => {
        console.warn(`[ZIFT-SHIELD] 🌐 Outbound Connection: ${address}:${port}`);
    });

    // 2. Wrap Child Process (for shell command execution) - ACTIVE BLOCKING
    const cp = require('node:child_process');
    let ALLOWED_COMMANDS = ['npm install', 'npm audit', 'ls', 'dir', 'whoami', 'node -v'];

    if (manifest && manifest.capabilities && manifest.capabilities.shell) {
        if (manifest.capabilities.shell.enabled === false) {
            ALLOWED_COMMANDS = [];
        } else if (Array.isArray(manifest.capabilities.shell.allowList)) {
            ALLOWED_COMMANDS = manifest.capabilities.shell.allowList;
        }
    }

    ['exec', 'spawn', 'execSync', 'spawnSync'].forEach(method => {
        const original = cp[method];
        if (!original) return;

        const wrapper = function (...args) {
            const command = args[0];
            const cmdStr = typeof command === 'string' ? command : (Array.isArray(args[1]) ? args[1].join(' ') : String(command));

            // Security Logic
            const isCritical = cmdStr.includes('curl') || cmdStr.includes('wget') || cmdStr.includes('| sh') || cmdStr.includes('| bash') || cmdStr.includes('rm -rf /');
            const isBlocked = !ALLOWED_COMMANDS.some(allowed => cmdStr.startsWith(allowed)) || isCritical;

            if (isBlocked) {
                console.error(`[ZIFT-SHIELD] ❌ BLOCKED: Unauthorized or dangerous shell execution: "${cmdStr}"`);
                if (process.env.ZIFT_ENFORCE === 'true') {
                    throw new Error(`[ZIFT-SHIELD] Access Denied: Shell command "${cmdStr}" is not in the allow-list.`);
                }
            } else {
                console.warn(`[ZIFT-SHIELD] 🐚 Shell Execution (Allowed): ${cmdStr}`);
            }

            return original.apply(this, args);
        };

        try {
            Object.defineProperty(cp, method, { value: wrapper, writable: false, configurable: false });
        } catch (e) {
            cp[method] = wrapper; // Fallback
        }
    });

    // 2.5 Filesystem Protection
    const fs = require('node:fs');
    let PROTECTED_FILES = ['.env', '.npmrc', 'shadow', 'id_rsa', 'id_ed25519'];
    let blockAllFiles = false;

    if (manifest && manifest.capabilities && manifest.capabilities.filesystem) {
        if (manifest.capabilities.filesystem.read === false) {
            blockAllFiles = true;
        } else if (Array.isArray(manifest.capabilities.filesystem.read)) {
            // Remove allowed paths from PROTECTED_FILES if they match exactly
            PROTECTED_FILES = PROTECTED_FILES.filter(f => !manifest.capabilities.filesystem.read.includes(f));
        }
    }

    const fsMethods = ['readFile', 'readFileSync', 'promises.readFile', 'createReadStream'];
    fsMethods.forEach(methodPath => {
        let parent = fs;
        let method = methodPath;
        if (methodPath.startsWith('promises.')) {
            parent = fs.promises;
            method = 'readFile';
        }

        const original = parent[method];
        if (!original) return;

        const wrapper = function (...args) {
            const pathArg = args[0];
            const pathStr = typeof pathArg === 'string' ? pathArg : (pathArg instanceof Buffer ? pathArg.toString() : String(pathArg));

            if (blockAllFiles || PROTECTED_FILES.some(f => pathStr.includes(f))) {
                console.error(`[ZIFT-SHIELD] ❌ BLOCKED: Access to restricted file: "${pathStr}"`);
                if (process.env.ZIFT_ENFORCE === 'true') {
                    throw new Error(`[ZIFT-SHIELD] Access Denied: File path "${pathStr}" is restricted by Zero-Trust policy.`);
                }
            }
            return original.apply(this, args);
        };

        try {
            Object.defineProperty(parent, method, { value: wrapper, writable: false, configurable: false });
        } catch (e) {
            parent[method] = wrapper;
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
