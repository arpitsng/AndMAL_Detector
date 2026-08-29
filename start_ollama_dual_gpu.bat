@echo off
echo ===================================================
echo Starting Ollama with Full Dual-GPU CUDA Offloading
echo ===================================================

echo [1/3] Stopping background services...
powershell -Command "Stop-Service -Name OllamaDaemon -Force -ErrorAction SilentlyContinue" >nul 2>&1
taskkill /F /IM ollama* >nul 2>&1

echo [2/3] Configuring clean CUDA environment...
set "CUDA_VISIBLE_DEVICES="
set "GPU_DEVICE_ORDINAL="
set "OLLAMA_MODELS=C:\WINDOWS\system32\config\systemprofile\.ollama\models"
set "OLLAMA_FLASH_ATTENTION=1"
set "OLLAMA_NUM_PARALLEL=1"

echo [3/3] Launching Ollama GPU Server...
echo (Keep this window open while running inference)
echo.
"%LOCALAPPDATA%\Programs\Ollama\ollama.exe" serve
