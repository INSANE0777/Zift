const PackageScanner = require('../src/scanner');
const fs = require('node:fs');
const path = require('node:path');

async function runTest() {
    const sampleDir = path.join(__dirname, 'samples');
    const scanner = new PackageScanner(sampleDir);

    console.log('--- Running Safety Watch Test ---');
    const findings = await scanner.scan();

    if (findings.length > 0) {
        console.log(`✅ Success: Detected ${findings.length} findings.`);
        findings.forEach(f => {
            console.log(` - [${f.classification}] ${f.ruleId} (Score: ${f.score})`);
        });

        const hasExfil = findings.some(f => f.ruleId === 'ENV_EXFILTRATION');
        if (hasExfil) {
            console.log('✅ Success: Correctly identified ENV_EXFILTRATION.');
        } else {
            console.log('❌ Failure: Did not detect ENV_EXFILTRATION.');
            process.exit(1);
        }
    } else {
        console.log('❌ Failure: No findings detected.');
        process.exit(1);
    }
}

runTest().catch((err) => {
    console.error(err);
    process.exit(1);
});
