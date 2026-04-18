#!/usr/bin/env pwsh
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Write-Host 'Installing npm workspace dependencies...'
npm install
Write-Host 'Installing Rust workspace dependencies...'
cargo fetch
Write-Host 'Building Rust workspace...'
cargo build
Write-Host 'Starting HexHawk Tauri dev mode...'
npm --workspace HexHawk run tauri:dev
