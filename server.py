import sys
import threading
from socket import *

server_address = '127.0.0.1'
server_port = 65432
serv = socket(AF_INET,SOCK_STREAM)
serv.bind((server_address, server_port))
serv.listen(25)
client, address = serv.accept()
client.send("Hi I am server".encode('utf-8'))
data = client.recv(1024)
print(data.decode('utf-8'))
serv.close()