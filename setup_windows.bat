@echo off
:: =============================================================================
::  LAMD Project — Windows Environment Setup Script
::  File: setup_windows.bat
::
::  Purpose:
::    Bootstraps a fully isolated, reproducible local development environment
::    for the LAMD hybrid Python/Java pipeline on Windows. Running this script
::    once is all a new team member needs to get started.
::
::  What this script does:
::    1. Creates all required project directories.
::    2. Creates a Python virtual environment (venv) to sandbox Python packages.
::    3. Installs the exact pinned Python dependencies from requirements.txt.
::    4. Reminds you to set up your .env file with the AndroZoo API key.
::
::  Note on Java / Maven:
::    The Soot slicer JAR must be compiled separately. With Java 17+ installed:
::      cd Slicer
::      mvn clean package -DskipTests
::    The compiled JAR (Slicer\target\slicer-1.0.jar) is then invoked directly
::    by the Python pipeline scripts via  java -jar.
::
::  Prerequisites:
::    - Python 3.8+   → https://www.python.org/downloads/
::    - Java 17+      → https://adoptium.net/  (needed to run the Soot JAR)
::    - Apache Maven  → https://maven.apache.org/  (only needed to build the JAR once)
::
::  Usage:
::    cd d:\LAMD_Project
::    setup_windows.bat
:: =============================================================================

echo.
echo =====================================================================
echo   LAMD Environment Setup for Windows
echo =====================================================================
echo.


:: =============================================================================
::  STEP 1 — Create project directory structure
::  "2>nul" suppresses the "already exists" error so the script is safe
::  to run multiple times without producing false failure output.
:: =============================================================================
echo [1/3] Creating project directory structure...

mkdir data\logs      2>nul
mkdir apks           2>nul
mkdir extracted_cfgs 2>nul
mkdir src_python     2>nul

echo       data\logs       ... OK
echo       apks            ... OK
echo       extracted_cfgs  ... OK
echo       src_python      ... OK
echo.


:: =============================================================================
::  STEP 2 — Create the Python virtual environment
::  This sandboxes all Python packages inside venv\ so they don't pollute
::  the system Python. The venv\ folder is gitignored — each developer
::  has their own isolated copy.
:: =============================================================================
echo [2/3] Creating Python virtual environment (venv)...

python -m venv venv
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to create the Python virtual environment.
    echo         Is Python 3.8+ installed and visible on your PATH?
    echo         Verify with:  python --version
    echo.
    goto :error
)

echo       Virtual environment created at: %~dp0venv\
echo.

:: Activate the venv so that pip in the next step targets the venv,
:: not the global Python install.
:: NOTE: "call" is mandatory — without it the batch script exits when
::       activate.bat finishes instead of returning control here.
call venv\Scripts\activate
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Could not activate the virtual environment.
    echo         Expected script at: venv\Scripts\activate.bat
    echo.
    goto :error
)


:: =============================================================================
::  STEP 3 — Install pinned Python dependencies
::  pip reads requirements.txt and installs EXACT pinned versions, so every
::  team member's environment is byte-for-byte identical.
:: =============================================================================
echo [3/3] Installing Python dependencies from requirements.txt...

pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] pip install failed. Possible causes:
    echo           - No internet connection.
    echo           - A package version in requirements.txt is unavailable.
    echo           - The virtual environment was not activated correctly.
    echo.
    goto :error
)

echo       Python dependencies installed successfully.
echo.


:: =============================================================================
::  SUCCESS
:: =============================================================================
echo.
echo =====================================================================
echo.
echo   SETUP COMPLETE!
echo.
echo   NEXT STEP — Configure your AndroZoo API key:
echo.
echo     1. Copy the template:
echo          copy .env.example .env
echo.
echo     2. Open .env in a text editor and replace the placeholder:
echo          ANDROZOO_API_KEY=your_androzoo_api_key_here
echo.
echo     3. Save .env  (it is gitignored — your key stays private).
echo.
echo   TO START WORKING, activate the venv in a new terminal:
echo.
echo       venv\Scripts\activate
echo.
echo   Then run the pipeline scripts in order:
echo       python src_python\2_extract_cfg.py    ^<-- download + analyze + delete
echo       python src_python\3_build_dataset.py  ^<-- assemble JSONL for LLM
echo.
echo   NOTE: Build the Soot JAR first if you haven't already:
echo       cd Slicer
echo       mvn clean package -DskipTests
echo       cd ..
echo.
echo =====================================================================
echo.

goto :end


:: =============================================================================
::  ERROR handler
:: =============================================================================
:error
echo.
echo =====================================================================
echo   SETUP FAILED. Fix the error above and re-run. Safe to run again.
echo =====================================================================
echo.
exit /b 1


:end
