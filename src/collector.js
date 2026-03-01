const acorn = require('acorn');
const walk = require('acorn-walk');
const vm = require('node:vm');
const { calculateEntropy } = require('./utils/entropy');

class ASTCollector {
    constructor() {
        this.entropyThreshold = 4.8;
        this.maxFileSize = 512 * 1024;
        this.maxStringLengthForEntropy = 2048;
    }

    collect(code, filePath) {
        const facts = {
            ENV_READ: [],
            MASS_ENV_ACCESS: [],
            FILE_READ_SENSITIVE: [],
            NETWORK_SINK: [],
            DNS_SINK: [],
            RAW_SOCKET_SINK: [],
            DYNAMIC_EXECUTION: [],
            DYNAMIC_REQUIRE: [],
            OBFUSCATION: [],
            FILE_WRITE_STARTUP: [],
            SHELL_EXECUTION: [],
            ENCODER_USE: [],
            REMOTE_FETCH_SIGNAL: [],
            PIPE_TO_SHELL_SIGNAL: [],
            EXPORTS: [],
            IMPORTS: [],
            OPAQUE_STRING_SKIP: [],
            NON_DETERMINISTIC_SINK: [],
            CREDENTIAL_FILE_ACCESS: [],
            DISCORD_STORAGE_ACCESS: [],
            WEBHOOK_SINK: [],
            EVASION_ENVIRONMENT_CHECK: [],
            WALLET_HOOK: [],
            CICD_SECRET_ACCESS: [],
            WIPER_OPERATION: [],
            REGISTRY_TAMPER: [],
            MODULE_TAMPER: [],
            REVERSE_SHELL_BEHAVIOR: [],
            FINGERPRINT_SIGNAL: [],
            PUBLISH_SINK: []
        };
        const flows = [];
        const sourceCode = code;
        let envAccessCount = 0;

        let ast;
        try {
            ast = acorn.parse(code, { ecmaVersion: 2020, sourceType: 'module', locations: true });
        } catch (error) {
            try {
                ast = acorn.parse(code, { ecmaVersion: 2020, sourceType: 'script', locations: true });
            } catch (error_) {
                return { facts, flows };
            }
        }

        walk.ancestor(ast, {
            Literal: (node) => {
                if (typeof node.value === 'string' && node.value.length > 20) {
                    if (node.value.length > this.maxStringLengthForEntropy) {
                        // High Entropy Skip Warning
                        const sample = node.value.substring(0, 100);
                        const sampleEntropy = calculateEntropy(sample);
                        if (sampleEntropy > this.entropyThreshold) {
                            facts.OPAQUE_STRING_SKIP.push({
                                file: filePath,
                                line: node.loc.start.line,
                                reason: `Large string skipped (>2KB) but sample has high entropy (${sampleEntropy.toFixed(2)})`
                            });
                        }
                        return;
                    }
                    const entropy = calculateEntropy(node.value);
                    if (entropy > this.entropyThreshold) {
                        facts.OBFUSCATION.push({
                            file: filePath,
                            line: node.loc.start.line,
                            reason: `High entropy string (${entropy.toFixed(2)})`,
                            value: node.value.substring(0, 50) + (node.value.length > 50 ? '...' : '')
                        });
                    }
                }
            },
            ImportDeclaration: (node) => {
                const source = node.source.value;
                node.specifiers.forEach(spec => {
                    facts.IMPORTS.push({
                        file: filePath,
                        line: node.loc.start.line,
                        source,
                        local: spec.local.name,
                        imported: spec.type === 'ImportDefaultSpecifier' ? 'default' : (spec.imported ? spec.imported.name : null)
                    });
                });
            },
            ExportNamedDeclaration: (node) => {
                if (node.declaration) {
                    if (node.declaration.type === 'VariableDeclaration') {
                        node.declaration.declarations.forEach(decl => {
                            facts.EXPORTS.push({
                                file: filePath,
                                line: node.loc.start.line,
                                name: decl.id.name,
                                type: 'named'
                            });
                        });
                    } else if (node.declaration.id) {
                        facts.EXPORTS.push({
                            file: filePath,
                            line: node.loc.start.line,
                            name: node.declaration.id.name,
                            type: 'named'
                        });
                    }
                }
                node.specifiers.forEach(spec => {
                    facts.EXPORTS.push({
                        file: filePath,
                        line: node.loc.start.line,
                        name: spec.exported.name,
                        local: spec.local.name,
                        type: 'named'
                    });
                });
            },
            ExportDefaultDeclaration: (node) => {
                facts.EXPORTS.push({
                    file: filePath,
                    line: node.loc.start.line,
                    name: 'default',
                    local: (node.declaration.id ? node.declaration.id.name : (node.declaration.name || null)),
                    type: 'default'
                });
            },
            Identifier: (node) => {
                const evasionIds = ['v8debug'];
                if (evasionIds.includes(node.name)) {
                    facts.EVASION_ENVIRONMENT_CHECK.push({
                        file: filePath,
                        line: node.loc.start.line,
                        context: node.name
                    });
                }
            },
            MemberExpression: (node, state, ancestors) => {
                const memberCode = sourceCode.substring(node.start, node.end);

                // 1. Anti-Analysis / Evasion Check
                const evasionPatterns = ['debugPort', 'v8debug', 'NODE_OPTIONS'];
                if (evasionPatterns.some(p => memberCode.includes(p))) {
                    facts.EVASION_ENVIRONMENT_CHECK.push({
                        file: filePath,
                        line: node.loc.start.line,
                        context: memberCode
                    });
                }

                // 2. Wallet DRAINER Hook detection
                const walletPatterns = ['ethereum', 'solana', 'phantom'];
                if (walletPatterns.some(p => memberCode.includes(p))) {
                    facts.WALLET_HOOK.push({
                        file: filePath,
                        line: node.loc.start.line,
                        context: memberCode
                    });
                }

                // 3. CI/CD Secret Access
                const cicdPatterns = ['GITHUB_TOKEN', 'CIRCLECI_TOKEN', 'AZURE_TOKEN', 'TRAVIS_TOKEN', 'GITLAB_TOKEN'];
                if (cicdPatterns.some(p => memberCode.includes(p))) {
                    facts.CICD_SECRET_ACCESS.push({
                        file: filePath,
                        line: node.loc.start.line,
                        variable: memberCode
                    });
                }

                // 4. OS Fingerprinting (platform, arch, release)
                const fingerPatterns = ['process.platform', 'process.arch', 'os.platform', 'os.arch', 'os.release', 'os.type'];
                if (fingerPatterns.some(p => memberCode.includes(p))) {
                    // Avoid duplicate if it's part of a CallExpression (will be caught there)
                    const parent = ancestors[ancestors.length - 2];
                    if (parent && parent.type === 'CallExpression' && parent.callee === node) return;

                    facts.FINGERPRINT_SIGNAL.push({
                        file: filePath,
                        line: node.loc.start.line,
                        context: memberCode
                    });
                }

                // 4. process.env access (Moved from redundant visitor)
                const objectCode = sourceCode.substring(node.object.start, node.object.end);
                if (objectCode === 'process.env' || objectCode === 'process["env"]' || objectCode === "process['env']") {
                    const property = node.property.name || (node.property.type === 'Literal' ? node.property.value : null);
                    const whitelist = ['NODE_ENV', 'TIMING', 'DEBUG', 'VERBOSE', 'CI', 'APPDATA', 'HOME', 'USERPROFILE', 'PATH', 'PWD'];
                    if (whitelist.includes(property)) return;

                    envAccessCount++;
                    facts.ENV_READ.push({
                        file: filePath,
                        line: node.loc.start.line,
                        variable: property ? `process.env.${property}` : 'process.env'
                    });

                    if (envAccessCount > 5) {
                        facts.MASS_ENV_ACCESS.push({ file: filePath, line: node.loc.start.line, count: envAccessCount });
                    }
                }
            },
            CallExpression: (node, state, ancestors) => {
                const calleeCode = sourceCode.substring(node.callee.start, node.callee.end);

                if (calleeCode === 'eval' || calleeCode === 'Function') {
                    facts.DYNAMIC_EXECUTION.push({
                        file: filePath,
                        line: node.loc.start.line,
                        type: calleeCode
                    });
                }

                if (calleeCode === 'require' && node.arguments.length > 0) {
                    if (node.arguments[0].type !== 'Literal') {
                        facts.DYNAMIC_REQUIRE.push({
                            file: filePath,
                            line: node.loc.start.line,
                            variable: sourceCode.substring(node.arguments[0].start, node.arguments[0].end)
                        });
                    } else {
                        const source = node.arguments[0].value;
                        const parent = ancestors[ancestors.length - 2];
                        if (parent && parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') {
                            facts.IMPORTS.push({
                                file: filePath, line: node.loc.start.line, source, local: parent.id.name, imported: 'default'
                            });
                        }
                    }
                }

                const evaluated = this.tryEvaluate(node, sourceCode);
                if (evaluated) {
                    if (this.getNetworkType(evaluated) || this.isShellSink(evaluated) || evaluated === 'eval' || evaluated === 'Function') {
                        facts.OBFUSCATION.push({
                            file: filePath,
                            line: node.loc.start.line,
                            reason: `De-obfuscated to: ${evaluated}`,
                            revealed: evaluated
                        });
                        if (evaluated === 'eval' || evaluated === 'Function') {
                            facts.DYNAMIC_EXECUTION.push({ file: filePath, line: node.loc.start.line, type: evaluated });
                        }
                    }
                }

                const netType = this.getNetworkType(calleeCode);
                if (netType) {
                    facts[netType].push({
                        file: filePath,
                        line: node.loc.start.line,
                        callee: calleeCode
                    });

                    // Check for Webhook Sinks
                    if (netType === 'NETWORK_SINK') {
                        node.arguments.forEach(arg => {
                            if (arg.type === 'Literal' && typeof arg.value === 'string') {
                                const val = arg.value.toLowerCase();
                                const webhooks = ['discord.com/api/webhooks', 'pipedream.net', 'webhook.site', 'burpcollaborator.net'];
                                if (webhooks.some(w => val.includes(w))) {
                                    facts.WEBHOOK_SINK.push({
                                        file: filePath,
                                        line: node.loc.start.line,
                                        url: val
                                    });
                                }
                            }
                        });
                    }
                }

                if (this.isShellSink(calleeCode)) {
                    facts.SHELL_EXECUTION.push({
                        file: filePath,
                        line: node.loc.start.line,
                        callee: calleeCode
                    });

                    node.arguments.forEach(arg => {
                        if (arg.type === 'Literal' && typeof arg.value === 'string') {
                            const val = arg.value.toLowerCase();
                            if ((val.includes('curl') || val.includes('wget') || val.includes('fetch')) && (val.includes('http') || val.includes('//'))) {
                                facts.REMOTE_FETCH_SIGNAL.push({ file: filePath, line: node.loc.start.line, context: val });
                            }
                            if (val.includes('| sh') || val.includes('| bash') || val.includes('| cmd') || val.includes('| pwsh')) {
                                facts.PIPE_TO_SHELL_SIGNAL.push({ file: filePath, line: node.loc.start.line, context: val });
                            }
                        }
                    });
                }

                if (this.isEncoder(calleeCode)) {
                    facts.ENCODER_USE.push({
                        file: filePath,
                        line: node.loc.start.line,
                        type: calleeCode
                    });
                }

                if (this.isSensitiveFileRead(calleeCode, node, sourceCode)) {
                    const arg = node.arguments[0];
                    const pathValue = arg && arg.type === 'Literal' ? String(arg.value).toLowerCase() : '';
                    const isCredential = ['.aws', '.ssh', '.npmrc', 'aws_access_key', 'shadow'].some(s => pathValue.includes(s));

                    if (isCredential) {
                        facts.CREDENTIAL_FILE_ACCESS.push({
                            file: filePath,
                            line: node.loc.start.line,
                            path: pathValue
                        });
                    } else {
                        facts.FILE_READ_SENSITIVE.push({
                            file: filePath,
                            line: node.loc.start.line,
                            path: sourceCode.substring(node.arguments[0].start, node.arguments[0].end)
                        });
                    }
                }

                if (this.isDiscordStorageAccess(calleeCode, node, sourceCode)) {
                    facts.DISCORD_STORAGE_ACCESS.push({
                        file: filePath,
                        line: node.loc.start.line,
                        path: sourceCode.substring(node.arguments[0].start, node.arguments[0].end)
                    });
                }

                if (this.isStartupFileWrite(calleeCode, node, sourceCode)) {
                    facts.FILE_WRITE_STARTUP.push({
                        file: filePath,
                        line: node.loc.start.line,
                        path: node.arguments[0] ? sourceCode.substring(node.arguments[0].start, node.arguments[0].end) : 'unknown'
                    });
                }

                if (this.isWiperOperation(calleeCode, node, sourceCode)) {
                    facts.WIPER_OPERATION.push({
                        file: filePath,
                        line: node.loc.start.line,
                        path: node.arguments[0] ? sourceCode.substring(node.arguments[0].start, node.arguments[0].end) : 'unknown'
                    });
                }

                if (this.isRegistryTamper(calleeCode, node, sourceCode)) {
                    facts.REGISTRY_TAMPER.push({
                        file: filePath,
                        line: node.loc.start.line,
                        path: node.arguments[0] ? sourceCode.substring(node.arguments[0].start, node.arguments[0].end) : 'unknown'
                    });
                }

                if (this.isModuleTamper(calleeCode, node, sourceCode)) {
                    facts.MODULE_TAMPER.push({
                        file: filePath,
                        line: node.loc.start.line,
                        path: node.arguments[0] ? sourceCode.substring(node.arguments[0].start, node.arguments[0].end) : 'unknown'
                    });
                }

                if (this.isReverseShellBehavior(calleeCode, node, sourceCode)) {
                    facts.REVERSE_SHELL_BEHAVIOR.push({
                        file: filePath,
                        line: node.loc.start.line,
                        context: calleeCode
                    });
                }

                if (this.isPublishSink(calleeCode, node, sourceCode)) {
                    facts.PUBLISH_SINK.push({
                        file: filePath,
                        line: node.loc.start.line,
                        callee: calleeCode
                    });
                }

                if (this.isOSFingerprint(calleeCode, node, sourceCode)) {
                    facts.FINGERPRINT_SIGNAL.push({
                        file: filePath,
                        line: node.loc.start.line,
                        context: calleeCode
                    });
                }

                node.arguments.forEach((arg, index) => {
                    const argCode = sourceCode.substring(arg.start, arg.end);
                    const isArgTainted = argCode.includes('process.env') || flows.some(f => {
                        const regex = new RegExp(`\\b${f.toVar}\\b`);
                        return regex.test(argCode);
                    });

                    if (isArgTainted) {
                        const funcNode = this.findFunctionDefinition(calleeCode, ast);
                        if (funcNode && funcNode.params[index]) {
                            const paramName = funcNode.params[index].name;
                            flows.push({
                                fromVar: argCode,
                                toVar: `${calleeCode}:${paramName}`,
                                file: filePath,
                                line: node.loc.start.line
                            });
                        }
                    }

                    // v4.0 Hardening: Non-deterministic constructor
                    if (['Math.random', 'Date.now', 'Date()'].some(t => argCode.includes(t))) {
                        if (evaluated === 'eval' || evaluated === 'Function' || this.isShellSink(calleeCode)) {
                            facts.NON_DETERMINISTIC_SINK.push({
                                file: filePath,
                                line: node.loc.start.line,
                                callee: calleeCode,
                                reason: `Sink uses non-deterministic argument (${argCode})`
                            });
                        }
                    }
                });

                // v5.2 Symbolic Async: await and .then()
                if (calleeCode.includes('.then')) {
                    const parts = calleeCode.split('.then');
                    const promiseBase = parts[0];
                    const isPromiseTainted = flows.some(f => f.toVar === promiseBase) || promiseBase.includes('process.env') || promiseBase.includes('secret');

                    if (isPromiseTainted && node.arguments[0] && (node.arguments[0].type === 'ArrowFunctionExpression' || node.arguments[0].type === 'FunctionExpression')) {
                        const param = node.arguments[0].params[0];
                        if (param && param.type === 'Identifier') {
                            flows.push({
                                fromVar: promiseBase,
                                toVar: param.name,
                                file: filePath,
                                line: node.loc.start.line,
                                async: true
                            });
                        }
                    }
                }

                // v5.1 Symbolic Mutations: .push(), .concat(), .assign()
                const mutationMethods = ['push', 'unshift', 'concat', 'assign', 'append'];
                if (mutationMethods.some(m => calleeCode.endsWith('.' + m))) {
                    const objectName = calleeCode.split('.')[0];
                    node.arguments.forEach(arg => {
                        const argCode = sourceCode.substring(arg.start, arg.end);
                        const isArgTainted = argCode.includes('process.env') || flows.some(f => f.toVar === argCode);
                        if (isArgTainted) {
                            flows.push({
                                fromVar: argCode,
                                toVar: objectName,
                                file: filePath,
                                line: node.loc.start.line,
                                mutation: calleeCode
                            });
                        }
                    });
                }

                // v5.0 Symbolic Transformers: Buffer/Base64/Hex
                if (calleeCode.includes('Buffer.from') || calleeCode.includes('.toString')) {
                    const parent = ancestors[ancestors.length - 2];
                    if (parent && parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') {
                        const arg = node.arguments[0] ? sourceCode.substring(node.arguments[0].start, node.arguments[0].end) : null;
                        if (arg) {
                            flows.push({
                                fromVar: arg,
                                toVar: parent.id.name,
                                file: filePath,
                                line: node.loc.start.line,
                                transformation: calleeCode.includes('base64') ? 'base64' : (calleeCode.includes('hex') ? 'hex' : 'buffer')
                            });
                        }
                    }
                }
            },
            VariableDeclarator: (node) => {
                if (node.init) {
                    const from = sourceCode.substring(node.init.start, node.init.end);
                    this.handlePattern(node.id, from, flows, filePath, node.loc.start.line);
                }
            },
            AssignmentExpression: (node) => {
                const leftCode = sourceCode.substring(node.left.start, node.left.end);
                if (node.right.type === 'AwaitExpression') {
                    const from = sourceCode.substring(node.right.argument.start, node.right.argument.end);
                    const isFromTainted = flows.some(f => f.toVar === from) || from.includes('process.env');
                    if (isFromTainted) {
                        flows.push({
                            fromVar: from,
                            toVar: leftCode,
                            file: filePath,
                            line: node.loc.start.line,
                            async: true
                        });
                    }
                }

                if (leftCode === 'module.exports' || leftCode.startsWith('exports.')) {
                    facts.EXPORTS.push({
                        file: filePath,
                        line: node.loc.start.line,
                        name: leftCode === 'module.exports' ? 'default' : leftCode.replace('exports.', ''),
                        local: (node.right.type === 'Identifier' ? node.right.name : null),
                        type: leftCode === 'module.exports' ? 'default' : 'named'
                    });
                }

                if (node.left.type === 'MemberExpression' && node.right.type === 'Identifier') {
                    const from = sourceCode.substring(node.right.start, node.right.end);
                    const to = sourceCode.substring(node.left.start, node.left.end);
                    flows.push({
                        fromVar: from,
                        toVar: to,
                        file: filePath,
                        line: node.loc.start.line
                    });
                } else if (node.left.type === 'ObjectPattern' || node.left.type === 'ArrayPattern') {
                    const from = sourceCode.substring(node.right.start, node.right.end);
                    this.handlePattern(node.left, from, flows, filePath, node.loc.start.line);
                }
            },
            ObjectExpression: (node, state, ancestors) => {
                const parent = ancestors[ancestors.length - 2];
                if (parent && parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') {
                    const objName = parent.id.name;
                    node.properties.forEach(prop => {
                        if (prop.value.type === 'MemberExpression' || prop.value.type === 'Identifier') {
                            const valCode = sourceCode.substring(prop.value.start, prop.value.end);
                            if (valCode.includes('process.env') || flows.some(f => f.toVar === valCode)) {
                                flows.push({
                                    fromVar: valCode,
                                    toVar: `${objName}.${sourceCode.substring(prop.key.start, prop.key.end)}`,
                                    file: filePath,
                                    line: prop.loc.start.line
                                });
                            }
                        }
                    });
                }
            }
        });

        return { facts, flows };
    }

    getNetworkType(calleeCode) {
        if (typeof calleeCode !== 'string') return null;
        const dnsSinks = ['dns.lookup', 'dns.resolve', 'dns.resolve4', 'dns.resolve6'];
        const rawSocketSinks = ['net.connect', 'net.createConnection'];
        const networkSinks = ['http.request', 'https.request', 'http.get', 'https.get', 'fetch', 'axios', 'request'];

        if (dnsSinks.some(sink => calleeCode === sink || calleeCode.endsWith('.' + sink))) return 'DNS_SINK';
        if (rawSocketSinks.some(sink => calleeCode === sink || calleeCode.endsWith('.' + sink))) return 'RAW_SOCKET_SINK';
        if (networkSinks.some(sink => {
            if (calleeCode === sink) return true;
            if (calleeCode.endsWith('.' + sink)) return true;
            if (sink.includes('.') && calleeCode.endsWith(sink.split('.')[1]) && calleeCode.includes(sink.split('.')[0])) return true;
            return false;
        })) return 'NETWORK_SINK';

        return null;
    }

    isShellSink(calleeCode) {
        if (typeof calleeCode !== 'string') return false;
        const shellSinks = ['child_process.exec', 'child_process.spawn', 'child_process.execSync', 'exec', 'spawn', 'execSync'];
        return shellSinks.some(sink => {
            if (calleeCode === sink) return true;
            if (calleeCode.endsWith('.' + sink)) return true;
            if (sink.includes('.') && calleeCode.endsWith(sink.split('.')[1]) && calleeCode.includes(sink.split('.')[0])) return true;
            return false;
        });
    }

    isEncoder(calleeCode) {
        if (typeof calleeCode !== 'string') return false;
        const encoders = ['Buffer.from', 'btoa', 'atob', 'zlib.deflate', 'zlib.gzip', 'crypto.createCipheriv'];
        return encoders.some(enc => calleeCode === enc || calleeCode.endsWith('.' + enc));
    }

    findFunctionDefinition(name, ast) {
        let found = null;
        walk.simple(ast, {
            FunctionDeclaration: (node) => {
                if (node.id.name === name) found = node;
            },
            VariableDeclarator: (node) => {
                if (node.id.name === name && node.init && (node.init.type === 'ArrowFunctionExpression' || node.init.type === 'FunctionExpression')) {
                    found = node.init;
                }
            }
        });
        return found;
    }

    isSensitiveFileRead(calleeCode, node, sourceCode) {
        if (typeof calleeCode !== 'string') return false;
        if (!calleeCode.includes('fs.readFile') && !calleeCode.includes('fs.readFileSync') &&
            !calleeCode.includes('fs.promises.readFile')) return false;

        if (node.arguments.length > 0 && node.arguments[0].type === 'Literal') {
            const pathValue = String(node.arguments[0].value);
            const sensitive = ['.ssh', '.env', 'shadow', 'passwd', 'credentials', 'token', '_netrc', 'aws_access_key', '.npmrc'];
            if (sensitive.some((s) => pathValue.includes(s))) return true;

            // Deep check: if argument is a variable, check if it was initialized with a sensitive string
            const arg = node.arguments[0];
            if (arg && arg.type === 'Identifier') {
                const varName = arg.name;
                // This is a bit complex for a one-liner, but we can check if it's in our local flows
                // For now, let's just stick to the code string includes, which already handles BinaryExpressions of literals
            }
        }
        return false;
    }

    isStartupFileWrite(calleeCode, node, sourceCode) {
        if (typeof calleeCode !== 'string') return false;
        if (!calleeCode.includes('fs.writeFile') && !calleeCode.includes('fs.writeFileSync') &&
            !calleeCode.includes('fs.appendFile')) return false;

        if (node.arguments.length > 0 && node.arguments[0].type === 'Literal') {
            const pathValue = String(node.arguments[0].value);
            const startup = ['package.json', '.npmrc', '.bashrc', '.zshrc', 'crontab', 'init.d', 'systemd'];
            return startup.some((s) => pathValue.toLowerCase().includes(s));
        }
        return false;
    }

    isDiscordStorageAccess(calleeCode, node, sourceCode) {
        if (typeof calleeCode !== 'string') return false;
        if (!calleeCode.includes('fs.readFile') && !calleeCode.includes('fs.readFileSync')) return false;

        if (node.arguments.length > 0) {
            const arg = node.arguments[0];
            const argCode = sourceCode.substring(arg.start, arg.end).toLowerCase();

            // Detection: check if the argument code OR any part of the expression contains 'discord' and 'local storage'
            // We also check identifiers if their names are suspicious (simple heuristic)
            return argCode.includes('discord') && (argCode.includes('local storage') || argCode.includes('leveldb') || argCode.includes('token'));
        }
        return false;
    }

    tryEvaluate(node, sourceCode) {
        try {
            const code = sourceCode.substring(node.start, node.end);
            if (code.includes('process') || code.includes('require') || code.includes('fs') || code.includes('child_process')) return null;
            if (!code.includes('[') && !code.includes('+') && !code.includes('join') && !code.includes('reverse')) return null;

            const script = new vm.Script(code);
            const context = vm.createContext({});
            const result = script.runInContext(context, { timeout: 50 });
            return typeof result === 'string' ? result : null;
        } catch (e) {
            return null;
        }
    }

    handlePattern(pattern, initCode, flows, filePath, line) {
        if (pattern.type === 'Identifier') {
            flows.push({ fromVar: initCode, toVar: pattern.name, file: filePath, line });
        } else if (pattern.type === 'ObjectPattern') {
            pattern.properties.forEach(prop => {
                if (prop.type === 'Property') {
                    const key = prop.key.type === 'Identifier' ? prop.key.name :
                        (prop.key.type === 'Literal' ? prop.key.value : null);
                    if (key) {
                        this.handlePattern(prop.value, `${initCode}.${key}`, flows, filePath, line);
                    }
                }
            });
        } else if (pattern.type === 'ArrayPattern') {
            pattern.elements.forEach((el, index) => {
                if (el) {
                    this.handlePattern(el, `${initCode}[${index}]`, flows, filePath, line);
                }
            });
        }
    }

    isWiperOperation(calleeCode, node, sourceCode) {
        if (typeof calleeCode !== 'string') return false;
        const wiperFuncs = ['fs.rm', 'fs.rmSync', 'fs.rmdir', 'fs.rmdirSync', 'fs.unlink', 'fs.unlinkSync'];
        const isWiperFunc = wiperFuncs.some(f => calleeCode === f || calleeCode.endsWith('.' + f));
        if (!isWiperFunc) return false;

        const arg = node.arguments[0];
        if (!arg) return false;

        const argCode = sourceCode.substring(arg.start, arg.end).toLowerCase();
        const sensitivePaths = ['/root', '/home', '/etc', '/var/log', '/usr/bin', '/bin', 'c:\\windows', 'c:\\users'];
        const isSensitivePath = sensitivePaths.some(p => argCode.includes(p));

        const hasRecursive = sourceCode.substring(node.start, node.end).includes('recursive: true');
        return isSensitivePath || hasRecursive;
    }

    isRegistryTamper(calleeCode, node, sourceCode) {
        if (typeof calleeCode !== 'string') return false;
        if (!calleeCode.includes('fs.writeFile') && !calleeCode.includes('fs.writeFileSync') && !calleeCode.includes('fs.appendFile')) return false;

        if (node.arguments.length > 0) {
            const arg = node.arguments[0];
            const argCode = sourceCode.substring(arg.start, arg.end).toLowerCase();
            return argCode.includes('.npmrc') || argCode.includes('registry') || argCode.includes('npm-registry');
        }
        return false;
    }

    isModuleTamper(calleeCode, node, sourceCode) {
        if (typeof calleeCode !== 'string') return false;
        if (!calleeCode.includes('fs.writeFile') && !calleeCode.includes('fs.writeFileSync') && !calleeCode.includes('fs.mkdir')) return false;

        if (node.arguments.length > 0) {
            const arg = node.arguments[0];
            const argCode = sourceCode.substring(arg.start, arg.end).toLowerCase();
            return argCode.includes('node_modules') || argCode.includes('.git');
        }
        return false;
    }

    isReverseShellBehavior(calleeCode, node, sourceCode) {
        if (typeof calleeCode !== 'string') return false;
        if (calleeCode.endsWith('.pipe')) {
            const arg = node.arguments[0];
            if (arg) {
                const argCode = sourceCode.substring(arg.start, arg.end);
                return ['process.stdin', 'process.stdout', 'sh', 'bash', 'cmd', 'pwsh'].some(s => argCode.includes(s));
            }
        }
        return false;
    }

    isPublishSink(calleeCode, node, sourceCode) {
        if (typeof calleeCode !== 'string') return false;

        // 1. Direct Shell Commands
        if (this.isShellSink(calleeCode)) {
            const arg = node.arguments[0];
            if (arg && arg.type === 'Literal' && typeof arg.value === 'string') {
                const val = arg.value.toLowerCase();
                if (val.includes('npm publish') || val.includes('npm login') || val.includes('npm adduser')) return true;
                if (val.includes('pnpm publish') || val.includes('yarn publish')) return true;
            }
        }

        // 2. Registry API calls (e.g. put to /-/package/)
        const networkSinks = ['fetch', 'axios', 'request', 'http.request', 'https.request'];
        const isNet = networkSinks.some(s => calleeCode === s || calleeCode.endsWith('.' + s));
        if (isNet && node.arguments.length > 0) {
            const arg = node.arguments[0];
            if (arg && arg.type === 'Literal' && typeof arg.value === 'string') {
                const val = arg.value.toLowerCase();
                if (val.includes('registry.npmjs.org') && (val.includes('/-/user/') || val.includes('/-/package/'))) return true;
            }
        }

        return false;
    }

    isOSFingerprint(calleeCode, node, sourceCode) {
        if (typeof calleeCode !== 'string') return false;

        // 1. OS Module Methods
        const osMethods = ['os.platform', 'os.arch', 'os.release', 'os.type', 'os.cpus', 'os.networkInterfaces', 'os.userInfo'];
        if (osMethods.some(m => calleeCode === m || calleeCode.endsWith('.' + m))) return true;

        // 2. File Reads of OS metadata
        if (calleeCode.includes('fs.readFile') || calleeCode.includes('fs.readFileSync')) {
            const arg = node.arguments[0];
            if (arg && arg.type === 'Literal' && typeof arg.value === 'string') {
                const val = arg.value.toLowerCase();
                if (val.includes('/etc/os-release') || val.includes('/etc/issue') || val.includes('/proc/version')) return true;
            }
        }

        return false;
    }
}

module.exports = ASTCollector;
