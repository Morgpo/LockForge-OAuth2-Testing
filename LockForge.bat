@echo off
echo Installing LockForge Web App dependencies

:: Check if virtual environment exists, if not create it
if not exist venv (
    echo Creating virtual environment
    python -m venv venv
    call .\venv\Scripts\activate
    echo Installing dependencies
    pip install -r requirements.txt
) else (
    call .\venv\Scripts\activate
)

cls
echo Starting LockForge Web App
flask --app LockForge.py --debug run