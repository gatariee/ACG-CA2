Write-Host "Checking python version..." -ForegroundColor White
$python_version = (python --version)
if ($python_version -match "^Python\s3\.([0-9]+)\.") {
    $version = [int]$Matches[1]
    if ($version -ge 9) {
        Write-Host "Python 3.9 or higher is installed..." -ForegroundColor Green
    } else {
        Write-Host "Python 3.9 or higher is not installed..." -ForegroundColor Red
        Write-Host "Please install Python 3.9 or higher from the official website" -ForegroundColor Red
        exit
    }
} else {
    Write-Host "Could not determine the installed Python version." -ForegroundColor Yellow
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

Write-Host "Installation Successful, you may now exit the script" -ForegroundColor Green



