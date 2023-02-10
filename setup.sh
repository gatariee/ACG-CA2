#!/bin/bash
cd "$(dirname "$BASH_SOURCE")"
echo Checking python version...
python_version=$(python --version 2>&1)
if echo $python_version | grep -q '^Python\s3\.[0-9][0-9]*\.[0-9]\+'; then
    version=$(echo $python_version | grep -o '[0-9][0-9]*\.[0-9]\+' | cut -d '.' -f 2)
    if [ $version -ge 9 ]; then
        echo "Python 3.9 or later is installed..."
    else
        echo "Python 3.9 or later is not installed. Please install it and try again."
        exit
    fi
else
    echo "Could not determine the installed Python version."
    exit
fi

if [ -d "env" ]; then
  echo "Virtual environment already exists. Skipping setup..."
else
  echo "Creating virtual environment..."
  python -m venv env
fi
source env/Scripts/activate
pip install -r requirements.txt
echo "Setup Successful"
read -p "Press enter to continue..."
