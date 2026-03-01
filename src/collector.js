const acorn = require('acorn');
const walk = require('acorn-walk');
const { calculateEntropy } = require('./utils/entropy');

class ASTCollector {
    constructor() {
        this.facts = {
            ENV_READ: [],
            FILE_READ_SENSITIVE: [],
            NETWORK_SINK: [],
            DYNAMIC_EXECUTION: [],
            OBFUSCATION: [],
            FILE_WRITE_STARTUP: []
        };
        this.flows = [];
        this.entropyThreshold = 4.8;
        this.maxFileSize = 512 * 1024; // 512KB cap for static analysis
        this.maxStringLengthForEntropy = 2048; // Don't calculate entropy for massive blobs
    }

    collect(code, filePath) {
        this.sourceCode = code;
        let ast;
        try {
            ast = acorn.parse(code, { ecmaVersion: 2020, sourceType: 'module', locations: true });
        } catch (error) {
            try {
                ast = acorn.parse(code, { ecmaVersion: 2020, sourceType: 'script', locations: true });
            } catch (error_) {
                return { facts: this.facts, flows: this.flows };
            }
        }

        walk.ancestor(ast, {
            Literal: (node) => {
                if (typeof node.value === 'string' && node.value.length > 20 && node.value.length < this.maxStringLengthForEntropy) {
                    const entropy = calculateEntropy(node.value);
                    if (entropy > this.entropyThreshold) {
                        this.facts.OBFUSCATION.push({
                            file: filePath,
                            line: node.loc.start.line,
                            reason: `High entropy string (${entropy.toFixed(2)})`,
                            value: node.value.substring(0, 50) + (node.value.length > 50 ? '...' : '')
                        });
                    }
                }
            },
            CallExpression: (node) => {
                const calleeCode = this.getSourceCode(node.callee);

                if (calleeCode === 'eval' || calleeCode === 'Function') {
                    this.facts.DYNAMIC_EXECUTION.push({
                        file: filePath,
                        line: node.loc.start.line,
                        type: calleeCode
                    });
                }

                if (this.isNetworkSink(calleeCode)) {
                    this.facts.NETWORK_SINK.push({
                        file: filePath,
                        line: node.loc.start.line,
                        callee: calleeCode
                    });
                }

                if (this.isSensitiveFileRead(calleeCode, node)) {
                    this.facts.FILE_READ_SENSITIVE.push({
                        file: filePath,
                        line: node.loc.start.line,
                        path: node.arguments[0] ? this.getSourceCode(node.arguments[0]) : 'unknown'
                    });
                }
            },
            MemberExpression: (node) => {
                const objectCode = this.getSourceCode(node.object);
                if (objectCode === 'process.env' || objectCode === 'process["env"]' || objectCode === "process['env']") {
                    const property = node.property.name || (node.property.type === 'Literal' ? node.property.value : null);
                    const whitelist = ['NODE_ENV', 'TIMING', 'DEBUG', 'VERBOSE', 'CI', 'APPDATA', 'HOME', 'USERPROFILE', 'PATH', 'PWD'];
                    if (whitelist.includes(property)) return;

                    this.facts.ENV_READ.push({
                        file: filePath,
                        line: node.loc.start.line,
                        variable: property ? `process.env.${property}` : 'process.env'
                    });
                }
            },
            VariableDeclarator: (node) => {
                if (node.init && node.id.type === 'Identifier') {
                    const from = this.getSourceCode(node.init);
                    this.flows.push({
                        fromVar: from,
                        toVar: node.id.name,
                        file: filePath,
                        line: node.loc.start.line
                    });
                }
            },
            AssignmentExpression: (node) => {
                if (node.left.type === 'MemberExpression' && node.right.type === 'Identifier') {
                    // Track property assignments: obj.prop = taintedVar
                    const from = this.getSourceCode(node.right);
                    const to = this.getSourceCode(node.left);
                    this.flows.push({
                        fromVar: from,
                        toVar: to,
                        file: filePath,
                        line: node.loc.start.line
                    });
                }
            },
            ObjectExpression: (node, state, ancestors) => {
                // Track object literal property assignments: const x = { p: process.env }
                const parent = ancestors[ancestors.length - 2];
                if (parent && parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') {
                    const objName = parent.id.name;
                    node.properties.forEach(prop => {
                        if (prop.value.type === 'MemberExpression') {
                            const valCode = this.getSourceCode(prop.value);
                            if (valCode.includes('process.env')) {
                                this.flows.push({
                                    fromVar: valCode,
                                    toVar: `${objName}.${this.getSourceCode(prop.key)}`,
                                    file: filePath,
                                    line: prop.loc.start.line
                                });
                            }
                        }
                    });
                }
            }
        });

        return { facts: this.facts, flows: this.flows };
    }

    isNetworkSink(calleeCode) {
        const methodSinks = ['http.request', 'https.request', 'http.get', 'https.get', 'net.connect', 'dns.lookup', 'dns.resolve', 'fetch', 'axios'];

        // Match methods like http.request but avoid requestIdleCallback or local 'request' variables
        return methodSinks.some(sink => {
            return calleeCode === sink || calleeCode.endsWith('.' + sink);
        }) && !calleeCode.includes('IdleCallback');
    }

    isSensitiveFileRead(calleeCode, node) {
        if (!calleeCode.includes('fs.readFile') && !calleeCode.includes('fs.readFileSync') &&
            !calleeCode.includes('fs.promises.readFile')) return false;

        if (node.arguments.length > 0 && node.arguments[0].type === 'Literal') {
            const path = String(node.arguments[0].value);
            const sensitive = ['.ssh', '.env', 'shadow', 'passwd', 'credentials', 'token'];
            return sensitive.some((s) => path.toLowerCase().includes(s));
        }
        return false;
    }

    getSourceCode(node) {
        return this.sourceCode.substring(node.start, node.end);
    }
}

module.exports = ASTCollector;
