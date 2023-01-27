Write-Host "Checking python version..." -ForegroundColor White
if ((python --version) -eq "Python 3.11.0") {
    Write-Host "Python 3.11.0 is installed..." -ForegroundColor Green
} else {
    Write-Host "Python 3.11.0 is not installed..." -ForegroundColor Red
    Write-Host "Please install Python 3.11 from the official website" -ForegroundColor Red
    exit
}
if (Test-Path "env") {
    Write-Host "Virtual Environment already exists! Skipping install..." 
    ./env/Scripts/Activate.ps1
} else {
    Write-Host "Starting Virtual Environment..." -ForegroundColor Green
    python -m venv env
    ./env/Scripts/Activate.ps1
    Write-Host "Installing Python Dependencies..." -ForegroundColor Green
    pip install -r requirements.txt
}
$answer = Read-Host "Would you like to run the script? (y/n)"
if($answer -eq "y") {
    Write-Host "Starting Server and Client..." -ForegroundColor Green
    Start-Process powershell.exe -ArgumentList "cd server; python server.py"
    Start-Sleep -Seconds 2
    Start-Process powershell.exe -ArgumentList "cd client; python client.py"
} else {
    Write-Host "Exiting... You may run the script using instructions at README.md" -ForegroundColor Red
    exit
}



