const acorn = require('acorn');
const walk = require('acorn-walk');
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
            FILE_READ_SENSITIVE: [],
            NETWORK_SINK: [],
            DYNAMIC_EXECUTION: [],
            OBFUSCATION: [],
            FILE_WRITE_STARTUP: [],
            SHELL_EXECUTION: [],
            ENCODER_USE: []
        };
        const flows = [];
        const sourceCode = code;

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
                if (typeof node.value === 'string' && node.value.length > 20 && node.value.length < this.maxStringLengthForEntropy) {
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
            CallExpression: (node, state, ancestors) => {
                const calleeCode = sourceCode.substring(node.callee.start, node.callee.end);

                if (calleeCode === 'eval' || calleeCode === 'Function') {
                    facts.DYNAMIC_EXECUTION.push({
                        file: filePath,
                        line: node.loc.start.line,
                        type: calleeCode
                    });
                }

                if (calleeCode === 'require' && node.arguments.length > 0 && node.arguments[0].type !== 'Literal') {
                    facts.DYNAMIC_EXECUTION.push({
                        file: filePath,
                        line: node.loc.start.line,
                        type: 'dynamic_require',
                        variable: sourceCode.substring(node.arguments[0].start, node.arguments[0].end)
                    });
                }

                if (this.isNetworkSink(calleeCode)) {
                    facts.NETWORK_SINK.push({
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

                node.arguments.forEach((arg, index) => {
                    const argCode = sourceCode.substring(arg.start, arg.end);
                    // Improved check: Does the expression contain any variable we know is tainted?
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
                });
            },
            MemberExpression: (node) => {
                const objectCode = sourceCode.substring(node.object.start, node.object.end);
                if (objectCode === 'process.env' || objectCode === 'process["env"]' || objectCode === "process['env']") {
                    const property = node.property.name || (node.property.type === 'Literal' ? node.property.value : null);
                    const whitelist = ['NODE_ENV', 'TIMING', 'DEBUG', 'VERBOSE', 'CI', 'APPDATA', 'HOME', 'USERPROFILE', 'PATH', 'PWD'];
                    if (whitelist.includes(property)) return;

                    facts.ENV_READ.push({
                        file: filePath,
                        line: node.loc.start.line,
                        variable: property ? `process.env.${property}` : 'process.env'
                    });
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

    isNetworkSink(calleeCode) {
        const methodSinks = [
            'http.request', 'https.request', 'http.get', 'https.get',
            'net.connect', 'dns.lookup', 'dns.resolve', 'dns.resolve4', 'dns.resolve6',
            'fetch', 'axios', 'request'
        ];
        // Improved matching for require('https').get patterns
        return methodSinks.some(sink => {
            if (calleeCode === sink) return true;
            if (calleeCode.endsWith('.' + sink)) return true;
            // Catch cases like require('https').get
            if (sink.includes('.') && calleeCode.endsWith(sink.split('.')[1]) && calleeCode.includes(sink.split('.')[0])) return true;
            return false;
        }) && !calleeCode.includes('IdleCallback');
    }

    isShellSink(calleeCode) {
        const shellSinks = ['child_process.exec', 'child_process.spawn', 'child_process.execSync', 'exec', 'spawn', 'execSync'];
        return shellSinks.some(sink => {
            if (calleeCode === sink) return true;
            if (calleeCode.endsWith('.' + sink)) return true;
            if (sink.includes('.') && calleeCode.endsWith(sink.split('.')[1]) && calleeCode.includes(sink.split('.')[0])) return true;
            return false;
        });
    }

    isEncoder(calleeCode) {
        const encoders = ['Buffer.from', 'btoa', 'atob'];
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
        if (!calleeCode.includes('fs.readFile') && !calleeCode.includes('fs.readFileSync') &&
            !calleeCode.includes('fs.promises.readFile')) return false;

        if (node.arguments.length > 0 && node.arguments[0].type === 'Literal') {
            const pathValue = String(node.arguments[0].value);
            const sensitive = ['.ssh', '.env', 'shadow', 'passwd', 'credentials', 'token'];
            return sensitive.some((s) => pathValue.toLowerCase().includes(s));
        }
        return false;
    }

    getSourceCode(node) {
        return this.sourceCode.substring(node.start, node.end);
    }
}

module.exports = ASTCollector;
