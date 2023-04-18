import socket
import pickle
import os

main_server = ("127.0.0.1", 65435)

PORT = 65444

DIR_PATH = "/Users/dineshgadu/Desktop/PCS Project3/"

def handle_request(request):
    operation, args, data = request
    if operation == 'create':
        filename = args
        filepath = os.path.join(DIR_PATH, filename + ".txt")
        if not os.path.exists(DIR_PATH):
            os.makedirs(DIR_PATH)
        with open(filepath, 'w') as f:
            f.write('')
        return "OK"
    elif operation == 'write':
        filename = args
        filepath = os.path.join(DIR_PATH, filename + ".txt")
        with open(filepath, 'a') as f:
            f.write(data.decode('utf-8'))
        return "file updated in replica3"
    # Add other operations here
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("127.0.0.1", PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            request = pickle.loads(data)
            response = handle_request(request)
            print(response)
