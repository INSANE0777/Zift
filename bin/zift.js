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

  if (args[0] === 'setup') {
    await runSetup();
    return;
  }

  if (args[0] === 'install' || args[0] === 'i') {
    isInstallMode = true;
    target = args.find((a, i) => i > 0 && !a.startsWith('-')) || '.';
  }

  if (args.includes('--zift')) {
    isInstallMode = true;
    target = args.find(a => !a.startsWith('-') && !['install', 'i', 'npm'].includes(a)) || '.';
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--format' && args[i + 1]) {
      format = args[i + 1];
      i++;
    }
  }

  if (args.length === 0) {
    showHelp();
    return;
  }

  const isLocal = fs.existsSync(target) && fs.lstatSync(target).isDirectory();

  if (isLocal) {
    await runLocalScan(target, format);
  } else {
    await runRemoteAudit(target, format, isInstallMode);
  }
}

async function runSetup() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  console.log(chalk.blue.bold('\n🛡️  Zift Secure Alias Setup'));
  console.log(chalk.gray('Configure `npm install --zift` for automatic security audits.\n'));

  const question = chalk.white('Add the Zift secure wrapper to your shell profile? (y/n): ');

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
        console.log(chalk.green('\n✅ Setup complete! Profile updated.'));
        console.log(chalk.yellow.bold(`\nTo activate IMMEDIATELY, run this command:`));
        console.log(chalk.cyan.inverse(`  ${reloadCmd}  \n`));
        console.log(chalk.gray('Alternatively, simply restart your terminal.'));
      } catch (e) {
        console.error(chalk.red('\n❌ Setup failed: ') + e.message);
      }
    } else {
      console.log(chalk.yellow('\nSetup cancelled.'));
    }
  });
}

function setupWindows() {
  const psFunction = `
# Zift Secure Alias
function npm {
    if ($args -contains "--zift") {
        $pkg = $args | Where-Object { $_ -ne "install" -and $_ -ne "i" -and $_ -ne "--zift" } | Select-Object -First 1
        Write-Host "\n🛡️ Zift: Intercepting installation for audit...\n" -ForegroundColor Green
        npx @7nsane/zift@latest install $pkg
    } else {
        & (Get-Command npm.cmd).Definition @args
    }
}
`;
  const profilePath = cp.execSync('powershell -NoProfile -Command "echo $PROFILE"').toString().trim();
  const profileDir = path.dirname(profilePath);
  if (!fs.existsSync(profileDir)) fs.mkdirSync(profileDir, { recursive: true });
  fs.appendFileSync(profilePath, psFunction);
  return '. $PROFILE';
}

function setupUnix() {
  const bashFunction = `
# Zift Secure Alias
npm() {
  if [[ "$*" == *"--zift"* ]]; then
    pkg=$(echo "$@" | sed 's/install//g; s/ i //g; s/--zift//g' | xargs)
    npx @7nsane/zift@latest install $pkg
  else
    command npm "$@"
  fi
}
`;
  const home = os.homedir();
  const profiles = [path.join(home, '.bashrc'), path.join(home, '.zshrc')];
  let reloadTarget = '~/.zshrc';
  profiles.forEach(p => {
    if (fs.existsSync(p)) {
      fs.appendFileSync(p, bashFunction);
      if (p.endsWith('.bashrc')) reloadTarget = '~/.bashrc';
    }
  });
  return `source ${reloadTarget}`;
}

async function runLocalScan(targetDir, format) {
  const scanner = new PackageScanner(targetDir);
  if (format === 'text') console.log(chalk.blue(`\n🔍 Scanning local directory: ${path.resolve(targetDir)}`));
  try {
    const findings = await scanner.scan();
    handleFindings(findings, format, targetDir);
  } catch (err) { handleError(err, format); }
}

async function runRemoteAudit(packageName, format, installOnSuccess) {
  if (format === 'text') console.log(chalk.blue(`\n🌍 Remote Audit: Pre-scanning package '${packageName}'...`));
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zift-audit-'));
  try {
    cp.execSync(`npm pack ${packageName}`, { cwd: tmpDir, stdio: 'ignore' });
    const tarball = fs.readdirSync(tmpDir).find(f => f.endsWith('.tgz'));
    cp.execSync(`tar -xzf ${tarball}`, { cwd: tmpDir });
    const scanPath = path.join(tmpDir, 'package');
    const scanner = new PackageScanner(scanPath);
    const findings = await scanner.scan();
    handleFindings(findings, format, scanPath, true);

    if (format === 'text') {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      const promptText = findings.length > 0
        ? chalk.yellow(`\n⚠️  Suspicious patterns found. Still install '${packageName}'? (y/n): `)
        : chalk.blue(`\nAudit passed. Proceed with installation of '${packageName}'? (y/n): `);

      rl.question(promptText, (answer) => {
        rl.close();
        if (['y', 'yes'].includes(answer.toLowerCase())) {
          console.log(chalk.blue(`\n📦 Installing ${packageName}...`));
          cp.execSync(`npm install ${packageName}`, { stdio: 'inherit' });
          console.log(chalk.green(`\n✅ ${packageName} installed successfully.`));
        }
        cleanupAndExit(tmpDir, 0);
      });
    } else { cleanupAndExit(tmpDir, 0); }
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
  console.log(chalk.blue.bold('\n🛡️  Zift - The Elite Security Scanner\n'));
  console.log('Usage:');
  console.log('  zift setup           Configure secure npm wrapper');
  console.log('  zift install <pkg>   Audit and install package');
  console.log('  zift .               Scan local directory');
}

function cleanupAndExit(dir, code) {
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  process.exit(code);
}

function handleError(err, format) {
  console.error(chalk.red(`\n❌ Error: ${err.message}`));
  process.exit(1);
}

main();
