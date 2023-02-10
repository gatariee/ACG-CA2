@echo off
echo Checking python version...
for /f "tokens=*" %%a in ('python --version') do set version=%%a
if %version:~0,3% GEQ 3.9 (
    echo Python 3.9 or higher is installed...
) else (
    echo Python 3.9 or higher is not installed...
    echo Please install Python 3.9 or higher from the official website
    exit /b
)
if exist env (
    echo Virtual Environment already exists! Skipping install...
    call env\Scripts\Activate.bat
) else (
    echo Starting Virtual Environment...
    python -m venv env
    call env\Scripts\Activate.bat
    echo Installing Python Dependencies...
    pip install -r requirements.txt
)
set /p answer="Would you like to run the script? (y/n): "
if %answer% == y (
    echo Starting Server and Client...
    start "Server" cmd /k "cd server & python server.py"
    timeout 2
    cd client & python client.py
    exit
) else (
    echo Exiting... You may run the script using instructions at README.md
    exit
)