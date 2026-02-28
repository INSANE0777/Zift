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
                if (typeof node.value === 'string' && node.value.length > 5) {
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

                // Detect eval / Function
                if (calleeCode === 'eval' || calleeCode === 'Function') {
                    this.facts.DYNAMIC_EXECUTION.push({
                        file: filePath,
                        line: node.loc.start.line,
                        type: calleeCode
                    });
                }

                // Detect Sinks
                if (this.isNetworkSink(calleeCode)) {
                    this.facts.NETWORK_SINK.push({
                        file: filePath,
                        line: node.loc.start.line,
                        callee: calleeCode
                    });
                }

                // Detect Sources
                if (this.isSensitiveFileRead(calleeCode, node)) {
                    this.facts.FILE_READ_SENSITIVE.push({
                        file: filePath,
                        line: node.loc.start.line,
                        path: node.arguments[0] ? this.getSourceCode(node.arguments[0]) : 'unknown'
                    });
                }
            },
            MemberExpression: (node) => {
                const memberCode = this.getSourceCode(node);
                // Detect process.env
                if (memberCode === 'process.env' || memberCode.startsWith('process.env.')) {
                    this.facts.ENV_READ.push({
                        file: filePath,
                        line: node.loc.start.line,
                        variable: memberCode
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
            }
        });

        return { facts: this.facts, flows: this.flows };
    }

    isNetworkSink(calleeCode) {
        const sinks = [
            'http.request', 'https.request', 'http.get', 'https.get',
            'fetch', 'axios', 'request', 'net.connect', 'dns.lookup',
            'dns.resolve', 'child_process.exec', 'child_process.spawn'
        ];
        return sinks.some(sink => calleeCode.includes(sink));
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
