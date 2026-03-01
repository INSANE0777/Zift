const fs = require('node:fs');
const path = require('node:path');
const ASTCollector = require('./collector');
const LifecycleResolver = require('./lifecycle');
const SafetyEngine = require('./engine');
const { getHash } = require('./utils/hash');

class PackageScanner {
    constructor(packageDir) {
        this.packageDir = path.resolve(packageDir);
        this.collector = new ASTCollector();
        this.lifecycleResolver = new LifecycleResolver(this.packageDir);
        this.engine = new SafetyEngine();
    }

    async scan() {
        const { files: lifecycleFiles, scripts } = this.lifecycleResolver.resolve();
        const files = await this.getFiles();
        this.detectedLifecycleScripts = scripts; // Store for formatter

        // Initialize cache directory
        const cacheDir = path.join(this.packageDir, 'node_modules', '.zift-cache');
        if (!fs.existsSync(cacheDir)) {
            try { fs.mkdirSync(cacheDir, { recursive: true }); } catch (e) { }
        }

        let allFacts = {
            facts: {
                ENV_READ: [],
                FILE_READ_SENSITIVE: [],
                NETWORK_SINK: [],
                DYNAMIC_EXECUTION: [],
                OBFUSCATION: [],
                FILE_WRITE_STARTUP: [],
                SHELL_EXECUTION: [],
                ENCODER_USE: []
            },
            flows: []
        };

        const pkgVersion = require('../package.json').version;

        // Parallel processing with limited concurrency (8 files at a time)
        const concurrency = 8;
        for (let i = 0; i < files.length; i += concurrency) {
            const chunk = files.slice(i, i + concurrency);
            await Promise.all(chunk.map(async (file) => {
                const stats = fs.statSync(file);
                if (stats.size > 512 * 1024) return;

                const code = fs.readFileSync(file, 'utf8');
                const fileHash = getHash(code + pkgVersion);
                const cachePath = path.join(cacheDir, fileHash + '.json');

                let facts = {}, flows = [];

                if (fs.existsSync(cachePath)) {
                    // Cache hit: Load metadata
                    try {
                        const cached = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
                        facts = cached.facts || {};
                        flows = cached.flows || [];
                    } catch (e) {
                        // Corrupt cache: re-scan
                        const result = this.collector.collect(code, file);
                        facts = result.facts;
                        flows = result.flows;
                    }
                } else {
                    // Cache miss: Scan and save
                    const result = this.collector.collect(code, file);
                    facts = result.facts;
                    flows = result.flows;

                    try {
                        fs.writeFileSync(cachePath, JSON.stringify({ facts, flows }));
                    } catch (e) { }
                }

                // Merge facts (Synchronized)
                for (const category in facts) {
                    if (allFacts.facts[category]) {
                        allFacts.facts[category].push(...facts[category]);
                    }
                }
                allFacts.flows.push(...flows);
            }));
        }

        const findings = this.engine.evaluate(allFacts, lifecycleFiles);
        return this.formatFindings(findings);
    }

    async getFiles() {
        // Load .ziftignore
        const ziftIgnorePath = path.join(this.packageDir, '.ziftignore');
        let ignoreLines = ['node_modules', '.git', 'dist', 'build', 'coverage', 'test', 'tests'];
        if (fs.existsSync(ziftIgnorePath)) {
            const content = fs.readFileSync(ziftIgnorePath, 'utf8');
            ignoreLines = [...ignoreLines, ...content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))];
        }

        const getJsFiles = (dir) => {
            const results = [];
            const list = fs.readdirSync(dir);
            for (const file of list) {
                const fullPath = path.join(dir, file);
                const relativePath = path.relative(this.packageDir, fullPath);

                // Simple ignore check
                if (ignoreLines.some(pattern => relativePath.includes(pattern) || file === pattern)) continue;
                if (file.startsWith('.') && file !== '.ziftignore') continue;

                const stat = fs.statSync(fullPath);
                if (stat && stat.isDirectory()) {
                    results.push(...getJsFiles(fullPath));
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

        return {
            results: sorted.map(f => {
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
            }),
            lifecycleScripts: this.detectedLifecycleScripts
        };
    }
}

module.exports = PackageScanner;
