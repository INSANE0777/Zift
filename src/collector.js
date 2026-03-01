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
            NON_DETERMINISTIC_SINK: []
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

                // De-obfuscation Trigger
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
                    facts.FILE_READ_SENSITIVE.push({
                        file: filePath,
                        line: node.loc.start.line,
                        path: node.arguments[0] ? sourceCode.substring(node.arguments[0].start, node.arguments[0].end) : 'unknown'
                    });
                }

                if (this.isStartupFileWrite(calleeCode, node, sourceCode)) {
                    facts.FILE_WRITE_STARTUP.push({
                        file: filePath,
                        line: node.loc.start.line,
                        path: node.arguments[0] ? sourceCode.substring(node.arguments[0].start, node.arguments[0].end) : 'unknown'
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
            },
            MemberExpression: (node) => {
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
            VariableDeclarator: (node) => {
                if (node.init && node.id.type === 'Identifier') {
                    const from = sourceCode.substring(node.init.start, node.init.end);
                    flows.push({
                        fromVar: from,
                        toVar: node.id.name,
                        file: filePath,
                        line: node.loc.start.line
                    });
                }
            },
            AssignmentExpression: (node) => {
                const leftCode = sourceCode.substring(node.left.start, node.left.end);
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
            const sensitive = ['.ssh', '.env', 'shadow', 'passwd', 'credentials', 'token', '_netrc', 'aws_access_key'];
            return sensitive.some((s) => pathValue.toLowerCase().includes(s));
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
}

module.exports = ASTCollector;
