# lancer-ghidra

Rust clone of `ghidra`. Part of the Lancer ecosystem — a complete 2026 AI-era bug bounty toolkit.

🚧 **In development.**

## Build

### Windows
Double-click `build.bat` or run from cmd:
```
build.bat
```
Output: `build\lancer-ghidra.exe`

For a packaged dist build:
```
build-windows.bat
```
Output: `dist\lancer-ghidra-windows-x86_64\bin\lancer-ghidra.exe`

### Linux / macOS
```bash
./build-linux.sh
```
Output: `build/lancer-ghidra`

### Requirements
- [Rust / Cargo](https://rustup.rs)
- (Windows) Visual C++ Build Tools 2019/2022

## Status

Scaffold only — implementation per local `plan.md` (gitignored).
