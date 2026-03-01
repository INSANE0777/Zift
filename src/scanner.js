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

        // Initialize fact storage
        let allFacts = {
            facts: {
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
                LIFECYCLE_CONTEXT: [],
                EXPORTS: [],
                IMPORTS: [],
                NATIVE_BINARY_DETECTED: [],
                OPAQUE_STRING_SKIP: []
            },
            flows: []
        };

        const pkgVersion = require('../package.json').version;

        // Pass 1: Collection
        const concurrency = 8;
        for (let i = 0; i < files.length; i += concurrency) {
            const chunk = files.slice(i, i + concurrency);
            await Promise.all(chunk.map(async (file) => {
                if (file.endsWith('.node')) {
                    allFacts.facts.NATIVE_BINARY_DETECTED.push({
                        file,
                        reason: 'Compiled native binary detected (Opaque Payload)'
                    });
                    return;
                }
                const stats = fs.statSync(file);
                if (stats.size > 512 * 1024) return;

                const code = fs.readFileSync(file, 'utf8');
                const fileHash = getHash(code + pkgVersion);
                const cachePath = path.join(cacheDir, fileHash + '.json');

                let facts = {}, flows = [];

                if (fs.existsSync(cachePath)) {
                    try {
                        const cached = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
                        facts = cached.facts || {};
                        flows = cached.flows || [];
                    } catch (e) {
                        const result = this.collector.collect(code, file);
                        facts = result.facts;
                        flows = result.flows;
                    }
                } else {
                    const result = this.collector.collect(code, file);
                    facts = result.facts;
                    flows = result.flows;
                    try { fs.writeFileSync(cachePath, JSON.stringify({ facts, flows })); } catch (e) { }
                }

                if (lifecycleFiles.has(file)) {
                    facts.LIFECYCLE_CONTEXT = facts.LIFECYCLE_CONTEXT || [];
                    facts.LIFECYCLE_CONTEXT.push({ file, reason: 'Lifecycle script context detected' });
                }

                for (const category in facts) {
                    if (allFacts.facts[category]) allFacts.facts[category].push(...facts[category]);
                }
                allFacts.flows.push(...flows);
            }));
        }

        // Pass 2: Cross-File Taint Resolution
        this.resolveCrossFileTaint(allFacts);

        const findings = this.engine.evaluate(allFacts, lifecycleFiles);
        return this.formatFindings(findings);
    }

    resolveCrossFileTaint(allFacts) {
        const { facts, flows } = allFacts;
        const exportMap = new Map(); // file -> exportName -> localName/isTainted

        // 1. Build Export Map
        facts.EXPORTS.forEach(exp => {
            if (!exportMap.has(exp.file)) exportMap.set(exp.file, new Map());

            // Check if localName is tainted in this file
            const isLocalTainted = flows.some(f => f.file === exp.file && f.toVar === exp.local && f.fromVar.includes('process.env'));
            const isNamedTainted = flows.some(f => f.file === exp.file && f.toVar === exp.name && f.fromVar.includes('process.env'));

            exportMap.get(exp.file).set(exp.name, {
                local: exp.local,
                isTainted: isLocalTainted || isNamedTainted
            });
        });

        // 2. Propagate to Imports
        facts.IMPORTS.forEach(imp => {
            let resolvedPath;
            if (imp.source.startsWith('.')) {
                resolvedPath = path.resolve(path.dirname(imp.file), imp.source);
                if (!resolvedPath.endsWith('.js')) resolvedPath += '.js';
            }

            if (resolvedPath && exportMap.has(resolvedPath)) {
                const targetExports = exportMap.get(resolvedPath);
                const matchedExport = targetExports.get(imp.imported);

                if (matchedExport && matchedExport.isTainted) {
                    // Mark as a virtual ENV_READ in the importing file
                    facts.ENV_READ.push({
                        file: imp.file,
                        line: imp.line,
                        variable: `[Cross-File] ${imp.local} (from ${imp.source})`,
                        isCrossFile: true
                    });
                }
            }
        });
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
                } else if (file.endsWith('.js') || file.endsWith('.node')) {
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
