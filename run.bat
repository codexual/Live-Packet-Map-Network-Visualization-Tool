@echo off
title Live Packet Map - 1337 Hacker Mode
color 0a
echo Initializing Packet Visualization System...
echo ----------------------------------------

:: Change directory to the location of this batch file
cd /d "%~dp0"

echo Python Version:
python --version

echo Listing static files:
if exist static (
    dir static
) else (
    echo No "static" folder found.
)

echo Listing data files:
if exist data (
    dir data
) else (
    echo No "data" folder found.
)

echo Environment variables:
set

echo Network info:
ipconfig

echo.
echo Starting backend server...
echo --------------------------
python app.py

echo.
echo ==== SYSTEM TERMINATED ====
pause
