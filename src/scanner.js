const fs = require('node:fs');
const path = require('node:path');
const ASTCollector = require('./collector');
const LifecycleResolver = require('./lifecycle');
const SafetyEngine = require('./engine');

class PackageScanner {
    constructor(packageDir) {
        this.packageDir = path.resolve(packageDir);
        this.collector = new ASTCollector();
        this.lifecycleResolver = new LifecycleResolver(this.packageDir);
        this.engine = new SafetyEngine();
    }

    async scan() {
        const lifecycleFiles = this.lifecycleResolver.resolve();
        const files = await this.getFiles();

        let allFacts = {
            facts: {
                ENV_READ: [],
                FILE_READ_SENSITIVE: [],
                NETWORK_SINK: [],
                DYNAMIC_EXECUTION: [],
                OBFUSCATION: [],
                FILE_WRITE_STARTUP: []
            },
            flows: []
        };

        for (const file of files) {
            const relativePath = path.relative(this.packageDir, file);
            if (relativePath.includes('node_modules') || relativePath.startsWith('.')) continue;

            const code = fs.readFileSync(file, 'utf8');
            const { facts, flows } = this.collector.collect(code, file);

            // Merge facts
            for (const category in facts) {
                allFacts.facts[category].push(...facts[category]);
            }
            allFacts.flows.push(...flows);
        }

        const findings = this.engine.evaluate(allFacts, lifecycleFiles);
        return this.formatFindings(findings);
    }

    async getFiles() {
        const getJsFiles = (dir) => {
            const results = [];
            const list = fs.readdirSync(dir);
            for (const file of list) {
                const fullPath = path.join(dir, file);
                const stat = fs.statSync(fullPath);
                if (stat && stat.isDirectory()) {
                    if (file !== 'node_modules' && file !== '.git') {
                        results.push(...getJsFiles(fullPath));
                    }
                } else if (file.endsWith('.js')) {
                    results.push(fullPath);
                }
            }
            return results;
        };
        return getJsFiles(this.packageDir);
    }

    formatFindings(findings) {
        const sorted = findings.sort((a, b) => b.score - a.score);

        return sorted.map(f => {
            let classification = 'Low';
            if (f.score >= 90) classification = 'Critical';
            else if (f.score >= 70) classification = 'High';
            else if (f.score >= 50) classification = 'Medium';

            return {
                ...f,
                classification,
                triggers: f.triggers.map(t => ({
                    type: t.type,
                    file: path.relative(this.packageDir, t.file),
                    line: t.line,
                    context: t.reason || t.callee || t.variable || t.path
                }))
            };
        });
    }
}

module.exports = PackageScanner;
