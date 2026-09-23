@echo off
title BloomRepo - Desktop GUI
cd /d "%~dp0"

if not exist "config.toml" (
    echo [ERROR] config.toml was not found in the project folder.
    pause
    exit /b 1
)

if not exist "target\release\bloomrepo.exe" (
    echo Compiling BloomRepo native binary...
    echo Internet access is required the first time to download Rust dependencies.
    cargo build --release --locked
    if errorlevel 1 (
        echo [ERROR] Failed to compile BloomRepo.
        echo Run this file from the project root and check your connection to crates.io.
        pause
        exit /b 1
    )
)

if not exist "target\release\bloomrepo.exe" (
    echo [ERROR] target\release\bloomrepo.exe was not created.
    pause
    exit /b 1
)

start "" "%~dp0target\release\bloomrepo.exe" --gui
