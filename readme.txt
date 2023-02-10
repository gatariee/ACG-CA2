Steps for setting up python installation:

Optional:
1. python -m venv env
2. ./env/Scripts/Activate.ps1 # activate environment 

Important:
1. pip install -r requirements.txt

Terminal 1:
1. cd server
2. python server.py

Terminal 2:
1. cd client
2. python client.py


Usage:
1. python server.py 
    - important !! run the server before the client
2. python client.py
    - AES and RSA keys will be initialized before the menu appears for the client.py
    - you may chosoe between get_menu and end_day
    - client.py will break if server.py is not running
3. After the server receives the day_end sales from the client, the data is automatically encrypted using the server's public key
4. You may decryption/encrypt this file by running the script located at /server/load_database.bat