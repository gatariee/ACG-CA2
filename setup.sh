#!/bin/bash
cd "$(dirname "$BASH_SOURCE")"
if python --version | grep -q '3.11.'; then
    echo "Python 3.11 is installed..."
else
    echo "Python 3.11 or later is not installed. Please install it and try again."
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
echo "Setup complete. Please follow the instructions at README.md"
read -p "Press enter to continue..."
