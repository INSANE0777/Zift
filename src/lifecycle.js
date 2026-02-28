const fs = require('fs');
const path = require('path');

class LifecycleResolver {
    constructor(packageDir) {
        this.packageDir = packageDir;
        this.lifecycleFiles = new Set();
    }

    resolve() {
        const packageJsonPath = path.join(this.packageDir, 'package.json');
        if (!fs.existsSync(packageJsonPath)) return this.lifecycleFiles;

        try {
            const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
            const scripts = pkg.scripts || {};

            const lifecycleHooks = ['preinstall', 'postinstall', 'install', 'preuninstall', 'postuninstall'];

            for (const hook of lifecycleHooks) {
                if (scripts[hook]) {
                    this.extractFilesFromScript(scripts[hook]);
                }
            }
        } catch (e) {
            // Ignore parse errors
        }

        return this.lifecycleFiles;
    }

    extractFilesFromScript(script) {
        // Look for "node file.js" or "node ./file.js"
        const nodeMatch = script.match(/node\s+([\w\.\/\-\\]+\.js)/g);
        if (nodeMatch) {
            for (const match of nodeMatch) {
                const filePath = match.replace(/node\s+/, '').trim();
                this.lifecycleFiles.add(path.resolve(this.packageDir, filePath));
            }
        }

        // Also look for direct script execution if it ends in .js
        const directMatch = script.match(/^([\w\.\/\-\\]+\.js)(\s|$)/);
        if (directMatch) {
            this.lifecycleFiles.add(path.resolve(this.packageDir, directMatch[1]));
        }
    }

    isLifecycleFile(filePath) {
        return this.lifecycleFiles.has(path.resolve(filePath));
    }
}

module.exports = LifecycleResolver;
