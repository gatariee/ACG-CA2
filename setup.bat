@echo off
echo Checking python version...
for /f "tokens=*" %%a in ('python --version') do set version=%%a
if "%version%"=="Python 3.11.0" (
    echo Python 3.11.0 is installed...
) else (   
    echo Python 3.11.0 is not installed...
    echo Please install Python 3.11 from the official website
    exit
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
    start "Client" cmd /k "cd client & python client.py"
) else (
    echo Exiting... You may run the script using instructions at README.md
    exit
)