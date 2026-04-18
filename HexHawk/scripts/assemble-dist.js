const fs = require('fs');
const path = require('path');

const projectRoot = path.resolve(__dirname, '..');
const bundleDir = path.join(projectRoot, 'src-tauri', 'target', 'release', 'bundle');
const outputRoot = path.resolve(projectRoot, '..', 'dist', 'HexHawk');
const repoReadme = path.resolve(projectRoot, '..', 'README.md');

if (!fs.existsSync(bundleDir)) {
  console.error('Bundle directory not found:', bundleDir);
  process.exit(1);
}

fs.mkdirSync(outputRoot, { recursive: true });

function copyRecursive(src, dest) {
  const stats = fs.statSync(src);
  if (stats.isDirectory()) {
    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      copyRecursive(path.join(src, entry), path.join(dest, entry));
    }
  } else {
    fs.copyFileSync(src, dest);
  }
}

copyRecursive(bundleDir, outputRoot);

if (fs.existsSync(repoReadme)) {
  fs.copyFileSync(repoReadme, path.join(outputRoot, 'README.md'));
}

console.log('Packaged HexHawk bundle to', outputRoot);
