const PackageScanner = require('../src/scanner');
const path = require('node:path');
const fs = require('node:fs');
const { execSync } = require('node:child_process');

async function benchmark() {
    const packages = ['react', 'express', 'eslint', 'typescript'];
    const tempDir = path.join(__dirname, 'temp_bench');

    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);

    console.log('--- Zift Real-World Benchmark ---');
    console.log(`Testing against: ${packages.join(', ')}\n`);

    const results = [];

    for (const pkg of packages) {
        console.log(`📦 Benchmarking ${pkg}...`);
        const pkgDir = path.join(tempDir, 'node_modules', pkg);

        // Install the package if not already there
        if (!fs.existsSync(pkgDir)) {
            try {
                execSync(`npm install ${pkg} --prefix ${tempDir} --no-save --no-audit --no-fund`, { stdio: 'ignore' });
            } catch (e) {
                console.error(`Failed to install ${pkg}: ${e.message}`);
                continue;
            }
        }

        const scanner = new PackageScanner(pkgDir);
        const start = Date.now();
        const findings = await scanner.scan();
        const duration = (Date.now() - start) / 1000;

        const criticalItems = findings.filter(f => f.classification === 'Critical');
        const highItems = findings.filter(f => f.classification === 'High');

        if (criticalItems.length > 0 || highItems.length > 0) {
            console.log(`\n🚨 Details for ${pkg}:`);
            [...criticalItems, ...highItems].forEach(f => {
                console.log(`- [${f.classification}] ${f.id} (${f.alias}): ${f.score}`);
                f.triggers.forEach(t => {
                    console.log(`  └─ ${t.type} @ ${t.file}:${t.line} (${t.context})`);
                });
            });
            console.log('');
        }

        const critical = findings.filter(f => f.classification === 'Critical').length;
        const high = findings.filter(f => f.classification === 'High').length;
        const medium = findings.filter(f => f.classification === 'Medium').length;
        const low = findings.filter(f => f.classification === 'Low').length;

        results.push({
            package: pkg,
            time: duration.toFixed(2) + 's',
            counts: { Critical: critical, High: high, Medium: medium, Low: low }
        });
    }

    console.table(results.map(r => ({
        Package: r.package,
        Time: r.time,
        Critical: r.counts.Critical,
        High: r.counts.High,
        Medium: r.counts.Medium,
        Low: r.counts.Low
    })));

    console.log('\n✅ Benchmark complete.');
}

benchmark().catch(err => {
    console.error(err);
    process.exit(1);
});
