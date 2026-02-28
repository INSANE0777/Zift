#!/usr/bin/env node
const PackageScanner = require('../src/scanner');
const chalk = require('chalk');
const path = require('node:path');
const fs = require('node:fs');
const cp = require('node:child_process');
const os = require('node:os');
const readline = require('node:readline');

async function main() {
  const args = process.argv.slice(2);
  let target = '.';
  let format = 'text';

  // Basic arg parsing
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--format' && args[i + 1]) {
      format = args[i + 1];
      i++;
    } else if (!args[i].startsWith('-')) {
      target = args[i];
    }
  }

  // Determine if target is local path or remote package
  const isLocal = fs.existsSync(target) && fs.lstatSync(target).isDirectory();

  if (isLocal) {
    await runLocalScan(target, format);
  } else {
    // Treat as remote package name
    await runRemoteAudit(target, format);
  }
}

async function runLocalScan(targetDir, format) {
  const scanner = new PackageScanner(targetDir);
  if (format === 'text') {
    process.stdout.write(chalk.blue(`\n🔍 Scanning local directory at ${path.resolve(targetDir)}...\n`));
  }

  try {
    const findings = await scanner.scan();
    handleFindings(findings, format, targetDir);
  } catch (err) {
    handleError(err, format);
  }
}

async function runRemoteAudit(packageName, format) {
  if (format === 'text') {
    console.log(chalk.blue(`\n🌍 Remote Audit: Attempting to pre-scan package '${packageName}'...`));
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zift-audit-'));

  try {
    // Download tarball
    cp.execSync(`npm pack ${packageName}`, { cwd: tmpDir, stdio: 'ignore' });
    const tarball = fs.readdirSync(tmpDir).find(f => f.endsWith('.tgz'));

    // Extract
    cp.execSync(`tar -xzf ${tarball}`, { cwd: tmpDir });
    const scanPath = path.join(tmpDir, 'package');

    const scanner = new PackageScanner(scanPath);
    const findings = await scanner.scan();

    // Custom reporting for remote audit
    if (format === 'text') {
      console.log(chalk.green(`✅ Pre-scan of '${packageName}' complete.`));
      const s = getSummary(findings);
      console.log(chalk.bold('Risk Profile: ') +
        (s.Critical > 0 ? chalk.red.bold('CRITICAL') :
          s.High > 0 ? chalk.red('HIGH') :
            s.Medium > 0 ? chalk.yellow('MEDIUM') : chalk.green('SECURE')));
    }

    handleFindings(findings, format, scanPath, true);

    // Interactive Prompt
    if (format === 'text') {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      const question = findings.length > 0
        ? chalk.yellow(`\n⚠️  Suspicious patterns found. Still install '${packageName}'? (yes/no): `)
        : chalk.blue(`\nProceed with installation of '${packageName}'? (yes/no): `);

      rl.question(question, (answer) => {
        rl.close();
        if (answer.toLowerCase() === 'yes' || answer.toLowerCase() === 'y') {
          console.log(chalk.blue(`\n📦 Installing ${packageName}...`));
          try {
            cp.execSync(`npm install ${packageName}`, { stdio: 'inherit' });
            console.log(chalk.green(`\n✅ ${packageName} installed successfully.`));
          } catch (e) {
            console.error(chalk.red(`\n❌ Installation failed.`));
          }
          cleanupAndExit(tmpDir, 0);
        } else {
          console.log(chalk.red(`\n❌ Installation aborted by user.`));
          cleanupAndExit(tmpDir, 0);
        }
      });
    } else {
      cleanupAndExit(tmpDir, 0);
    }

  } catch (err) {
    console.error(chalk.red(`\n❌ Remote Audit failed: Ensure '${packageName}' exists on npm.`));
    cleanupAndExit(tmpDir, 1);
  }
}

function handleFindings(findings, format, targetDir, skipExit = false) {
  if (format === 'json') {
    console.log(JSON.stringify({
      target: targetDir,
      timestamp: new Date().toISOString(),
      findings: findings,
      summary: getSummary(findings)
    }, null, 2));
    if (!skipExit) process.exit(findings.some(f => f.score >= 90) ? 1 : 0);
    return;
  }

  if (findings.length === 0) {
    if (!skipExit) {
      console.log(chalk.green('\n✅ No suspicious patterns detected. All modules within safety thresholds.'));
      process.exit(0);
    }
    return;
  }

  console.log(chalk.yellow(`\n⚠️  Found ${findings.length} suspicious patterns.\n`));

  findings.forEach(finding => {
    const colorMap = { 'Critical': chalk.red.bold, 'High': chalk.red, 'Medium': chalk.yellow, 'Low': chalk.blue };
    const theme = colorMap[finding.classification] || chalk.white;

    console.log(theme(`[${finding.classification}] ${finding.id} ${finding.name} (Risk Score: ${finding.score})`));
    console.log(chalk.gray(`Description: ${finding.description}`));

    finding.triggers.forEach(t => {
      console.log(chalk.white(`  - ${t.type} in ${t.file}:${t.line} [${t.context}]`));
    });

    if (finding.isLifecycle) {
      console.log(chalk.magenta(`  Context: Multiplier applied due to execution in lifecycle script.`));
    }
    console.log('');
  });

  printSummary(findings);

  if (!skipExit) {
    const highestScore = findings.length > 0 ? findings[0].score : 0;
    if (highestScore >= 90) {
      console.log(chalk.red.bold(`\n❌ FAILED SAFETY CHECK: Critical risk detected (Score: ${highestScore})\n`));
      process.exit(1);
    } else {
      console.log(chalk.green(`\n✔ Safety check completed with minor warnings.\n`));
      process.exit(0);
    }
  }
}

function cleanupAndExit(dir, code) {
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  if (code !== undefined) process.exit(code);
}

function handleError(err, format) {
  if (format === 'json') {
    console.error(JSON.stringify({ error: err.message }));
  } else {
    console.error(chalk.red(`\n❌ Fatal Error: ${err.message}`));
  }
  process.exit(1);
}

function getSummary(findings) {
  const summary = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach(f => {
    if (summary[f.classification] !== undefined) {
      summary[f.classification]++;
    }
  });
  return summary;
}

function printSummary(findings) {
  const s = getSummary(findings);
  console.log(chalk.bold('Severity Summary:'));
  console.log(chalk.red(`  Critical: ${s.Critical}`));
  console.log(chalk.red(`  High:     ${s.High}`));
  console.log(chalk.yellow(`  Medium:   ${s.Medium}`));
  console.log(chalk.blue(`  Low:      ${s.Low}`));
}

main();
