const fs = require('node:fs');
const path = require('node:path');

class LockfileAuditor {
    constructor(packageDir) {
        this.packageDir = packageDir;
        this.findings = [];
    }

    audit() {
        const lockfiles = [
            { name: 'package-lock.json', type: 'npm' },
            { name: 'pnpm-lock.yaml', type: 'pnpm' },
            { name: 'bun.lockb', type: 'bun' }
        ];

        for (const lock of lockfiles) {
            const fullPath = path.join(this.packageDir, lock.name);
            if (fs.existsSync(fullPath)) {
                this.auditLockfile(fullPath, lock.type);
            }
        }

        return this.findings;
    }

    auditLockfile(filePath, type) {
        const content = fs.readFileSync(filePath, 'utf8');

        if (type === 'npm') {
            try {
                const lock = JSON.parse(content);
                this.checkNpmDependencies(lock.dependencies || lock.packages || {});
            } catch (e) { }
        } else if (type === 'pnpm') {
            // pnpm-lock.yaml regex-based scanning (to avoid heavy yaml parser)
            this.scanTextForUntrustedSources(content, 'pnpm');
        } else if (type === 'bun') {
            // bun.lockb is binary, but often contains readable URLs or has a text counterpart
            this.scanTextForUntrustedSources(content, 'bun');
        }
    }

    scanTextForUntrustedSources(content, type) {
        // Look for git+ssh, git+https, github:, or non-npm https urls
        const lines = content.split('\n');
        lines.forEach((line, index) => {
            const gitMatch = line.match(/(git\+ssh|git\+https|github:|[a-zA-Z0-9.\-_]+\/[a-zA-Z0-9.\-_]+#[a-f0-9]+)/);
            if (gitMatch) {
                this.findings.push({
                    type: 'UNTRUSTED_GIT_SOURCE',
                    package: `Line ${index + 1}`,
                    source: gitMatch[0],
                    severity: 'Medium'
                });
            }

            const httpMatch = line.match(/https?:\/\/(?!(registry\.npmjs\.org|registry\.yarnpkg\.com))[a-zA-Z0-9.\-/_]+/);
            if (httpMatch) {
                this.findings.push({
                    type: 'NON_STANDARD_REGISTRY',
                    package: `Line ${index + 1}`,
                    source: httpMatch[0],
                    severity: 'High'
                });
            }
        });
    }

    checkNpmDependencies(deps) {
        for (const [name, info] of Object.entries(deps)) {
            if (!name) continue;

            const resolved = info.resolved || (info.version ? info.version : '');

            // Detect Git Dependencies
            if (resolved.includes('git+') || resolved.includes('github:')) {
                this.findings.push({
                    type: 'UNTRUSTED_GIT_SOURCE',
                    package: name,
                    source: resolved,
                    severity: 'Medium'
                });
            }

            // Detect HTTP based installs
            if (resolved.startsWith('http:') || (resolved.startsWith('https:') && !resolved.includes('registry.npmjs.org'))) {
                this.findings.push({
                    type: 'NON_STANDARD_REGISTRY',
                    package: name,
                    source: resolved,
                    severity: 'High'
                });
            }
        }
    }
}

module.exports = LockfileAuditor;
