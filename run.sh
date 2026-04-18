#!/usr/bin/env bash
set -euo pipefail
printf 'Installing npm workspace dependencies...\n'
npm install
printf 'Building Rust workspace...\n'
cargo build
printf 'Launching HexHawk Tauri dev server...\n'
npm --workspace HexHawk run tauri:dev
