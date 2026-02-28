#!/usr/bin/env node
const PackageScanner = require('../src/scanner');
const chalk = require('chalk');
const path = require('node:path');

async function main() {
  const args = process.argv.slice(2);
  let targetDir = '.';
  let format = 'text';

  // Basic arg parsing
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--format' && args[i + 1]) {
      format = args[i + 1];
      i++;
    } else if (!args[i].startsWith('-')) {
      targetDir = args[i];
    }
  }

  const scanner = new PackageScanner(targetDir);

  if (format === 'text') {
    process.stdout.write(chalk.blue(`\n🔍 Scanning package at ${path.resolve(targetDir)}...\n`));
  }

  try {
    const findings = await scanner.scan();

    if (format === 'json') {
      console.log(JSON.stringify({
        targetDir: path.resolve(targetDir),
        timestamp: new Date().toISOString(),
        findings: findings,
        summary: getSummary(findings)
      }, null, 2));
      process.exit(findings.some(f => f.score >= 90) ? 1 : 0);
    }

    if (findings.length === 0) {
      console.log(chalk.green('\n✅ No suspicious patterns detected. All modules within safety thresholds.'));
      process.exit(0);
    }

    console.log(chalk.yellow(`\n⚠️  Scan complete. Found ${findings.length} suspicious patterns.\n`));

    findings.forEach(finding => {
      const colorMap = {
        'Critical': chalk.red.bold,
        'High': chalk.red,
        'Medium': chalk.yellow,
        'Low': chalk.blue
      };

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

    const highestScore = findings.length > 0 ? findings[0].score : 0;
    if (highestScore >= 90) {
      console.log(chalk.red.bold(`\n❌ FAILED SAFETY CHECK: Critical risk detected (Score: ${highestScore})\n`));
      process.exit(1);
    } else {
      console.log(chalk.green(`\n✔ Safety check completed with minor warnings.\n`));
      process.exit(0);
    }

  } catch (err) {
    if (format === 'json') {
      console.error(JSON.stringify({ error: err.message }));
    } else {
      console.error(chalk.red(`\n❌ Fatal Error: ${err.message}`));
    }
    process.exit(1);
  }
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
