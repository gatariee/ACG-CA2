@echo off
start "Server" cmd /k "cd server & python server.py"
timeout 1
cd client & python client.py