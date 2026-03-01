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
  let isInstallMode = false;
  let installer = 'npm';

  // 1. Setup Command
  if (args[0] === 'setup') {
    await runSetup();
    return;
  }

  // 2. Detection for bun/pnpm usage
  if (args.includes('--bun')) installer = 'bun';
  if (args.includes('--pnpm')) installer = 'pnpm';

  // 3. Installation Verbs
  if (args[0] === 'install' || args[0] === 'i' || args[0] === 'add') {
    isInstallMode = true;
    target = args.find((a, i) => i > 0 && !a.startsWith('-')) || '.';
  }

  if (args.includes('--zift')) {
    isInstallMode = true;
    target = args.find(a => !a.startsWith('-') && !['install', 'i', 'add', 'npm', 'bun', 'pnpm'].includes(a)) || '.';
  }

  // 4. Flags
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--format' && args[i + 1]) {
      format = args[i + 1];
      i++;
    }
  }

  // 5. No Args? Show Help
  if (args.length === 0) {
    showHelp();
    return;
  }

  // 6. Execution
  const isLocal = fs.existsSync(target) && fs.lstatSync(target).isDirectory();

  if (isLocal) {
    await runLocalScan(target, format);
  } else {
    await runRemoteAudit(target, format, installer);
  }
}

async function runSetup() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  console.log(chalk.blue.bold('\n🛡️  Zift Secure Alias Setup (Universal)'));
  console.log(chalk.gray('Configure secure wrappers for npm, bun, and pnpm.\n'));

  const question = chalk.white('Add secure wrappers to your shell profile? (y/n): ');

  rl.question(question, (answer) => {
    rl.close();
    if (['y', 'yes'].includes(answer.toLowerCase())) {
      try {
        let reloadCmd = '';
        if (os.platform() === 'win32') {
          reloadCmd = setupWindows();
        } else {
          reloadCmd = setupUnix();
        }
        console.log(chalk.green('\n✅ Setup complete! All package managers are now secured.'));
        console.log(chalk.yellow.bold(`\nTo activate IMMEDIATELY, run: `) + chalk.cyan.inverse(` ${reloadCmd} `));
      } catch (e) {
        console.error(chalk.red('\n❌ Setup failed: ') + e.message);
      }
    }
  });
}

function setupWindows() {
  const psFunction = `
# Zift Secure Wrappers
function npm { if ($args -contains "--zift") { npx @7nsane/zift@latest install ($args | Where-Object { $_ -ne "install" -and $_ -ne "i" -and $_ -ne "--zift" } | Select-Object -First 1) } else { & (Get-Command npm.cmd).Definition @args } }
function bun { if ($args -contains "--zift") { npx @7nsane/zift@latest install ($args | Where-Object { $_ -ne "add" -and $_ -ne "install" -and $_ -ne "--zift" } | Select-Object -First 1) --bun } else { & (Get-Command bun.exe).Definition @args } }
function pnpm { if ($args -contains "--zift") { npx @7nsane/zift@latest install ($args | Where-Object { $_ -ne "add" -and $_ -ne "install" -and $_ -ne "i" -and $_ -ne "--zift" } | Select-Object -First 1) --pnpm } else { & (Get-Command pnpm.cmd).Definition @args } }
`;
  const profilePath = cp.execSync('powershell -NoProfile -Command "echo $PROFILE"').toString().trim();
  fs.appendFileSync(profilePath, psFunction);
  return '. $PROFILE';
}

function setupUnix() {
  const wrapperPattern = (cmd, aliasCmd) => `
${cmd}() {
  if [[ "$*" == *"--zift"* ]]; then
    pkg=$(echo "$@" | sed 's/install//g; s/add//g; s/ i //g; s/--zift//g' | xargs)
    npx @7nsane/zift@latest install $pkg --${cmd}
  else
    command ${cmd} "$@"
  fi
}
`;
  const shellFunctions = wrapperPattern('npm') + wrapperPattern('bun') + wrapperPattern('pnpm');
  const home = os.homedir();
  const profiles = [path.join(home, '.bashrc'), path.join(home, '.zshrc')];
  profiles.forEach(p => { if (fs.existsSync(p)) fs.appendFileSync(p, shellFunctions); });
  return 'source ~/.zshrc # or ~/.bashrc';
}

async function runRemoteAudit(packageName, format, installer) {
  if (format === 'text') console.log(chalk.blue(`\n🌍 Remote Audit [via ${installer}]: Pre-scanning '${packageName}'...`));
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zift-audit-'));
  try {
    cp.execSync(`npm pack ${packageName}`, { cwd: tmpDir, stdio: 'ignore' });
    const tarball = fs.readdirSync(tmpDir).find(f => f.endsWith('.tgz'));
    cp.execSync(`tar -xzf ${tarball}`, { cwd: tmpDir });
    const scanPath = path.join(tmpDir, 'package');
    const scanner = new PackageScanner(scanPath);
    const findings = await scanner.scan();
    handleFindings(findings, format, scanPath, true);

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const promptText = findings.length > 0
      ? chalk.yellow(`\n⚠️  Suspicious patterns found. Still install '${packageName}' with ${installer}? (y/n): `)
      : chalk.blue(`\nAudit passed. Proceed with installation of '${packageName}' via ${installer}? (y/n): `);

    rl.question(promptText, (answer) => {
      rl.close();
      if (['y', 'yes'].includes(answer.toLowerCase())) {
        console.log(chalk.blue(`\n📦 Running '${installer} install ${packageName}'...`));
        const installCmd = installer === 'bun' ? `bun add ${packageName}` : installer === 'pnpm' ? `pnpm add ${packageName}` : `npm install ${packageName}`;
        try { cp.execSync(installCmd, { stdio: 'inherit' }); } catch (err) { }
      }
      cleanupAndExit(tmpDir, 0);
    });
  } catch (err) { cleanupAndExit(tmpDir, 1); }
}

function handleFindings(findings, format, targetDir, skipExit = false) {
  if (format === 'json') {
    process.stdout.write(JSON.stringify({ target: targetDir, findings, summary: { Critical: findings.filter(f => f.classification === 'Critical').length, High: findings.filter(f => f.classification === 'High').length, Medium: findings.filter(f => f.classification === 'Medium').length, Low: findings.filter(f => f.classification === 'Low').length } }, null, 2));
    if (!skipExit) process.exit(findings.some(f => f.score >= 90) ? 1 : 0);
    return;
  }
  if (findings.length === 0) {
    if (!skipExit) { console.log(chalk.green('\n✅ No suspicious patterns detected. All modules safe.')); process.exit(0); }
    return;
  }
  findings.forEach(f => {
    const color = { 'Critical': chalk.red.bold, 'High': chalk.red, 'Medium': chalk.yellow, 'Low': chalk.blue }[f.classification];
    console.log(color(`[${f.classification}] ${f.id} ${f.name} (Score: ${f.score})`));
    f.triggers.forEach(t => console.log(chalk.white(`  - ${t.type} in ${t.file}:${t.line} [${t.context}]`)));
    console.log('');
  });
  if (!skipExit) process.exit(findings[0].score >= 90 ? 1 : 0);
}

function showHelp() {
  console.log(chalk.blue.bold('\n🛡️  Zift - Universal Security Scanner\n'));
  console.log('Usage:');
  console.log('  zift setup           Secure npm, bun, and pnpm');
  console.log('  zift install <pkg>   Scan and install package');
  console.log('  --bun / --pnpm       Use a specific installer');
}

function cleanupAndExit(dir, code) {
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  process.exit(code);
}

function handleError(err, format) {
  console.error(chalk.red(`\n❌ Error: ${err.message}`));
  process.exit(1);
}

function getSummary(findings) {
  const s = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach(f => s[f.classification]++);
  return s;
}

function printSummary(findings) {
  const s = getSummary(findings);
  console.log(chalk.bold('Severity Summary:'));
  console.log(chalk.red(`  Critical: ${s.Critical}\n  High:     ${s.High}`));
}

main();
