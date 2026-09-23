@echo off
title BloomRepo - Quick Check
cd /d "%~dp0"

if not exist "target\release\bloomrepo.exe" (
    echo Compiling BloomRepo native binary...
    cargo build --release --locked --offline
    if errorlevel 1 (
        echo Offline dependency cache is incomplete. Retrying with network access...
        cargo build --release --locked
        if errorlevel 1 (
            echo [ERROR] Failed to compile BloomRepo.
            echo Check your network connection to crates.io, then run this file again.
            pause
            exit /b 1
        )
    )
)

"target\release\bloomrepo.exe" --once
pause
