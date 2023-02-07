import subprocess

subprocess.Popen(["pwsh", "-Command", "cd server; python server.py"], creationflags=subprocess.CREATE_NEW_CONSOLE)
subprocess.run(["pwsh", "-Command", "cd client; python client.py"], shell=True)