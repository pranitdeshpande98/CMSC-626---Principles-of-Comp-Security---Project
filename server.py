import sys
import os
import threading
from socket import *
import mysql.connector
import datetime
from threading import Lock
import fcntl
import shutil
import rsa
import hashlib
import getpass
import getpass_asterisk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
def create_file(username):

    filename = input("Enter file name: ")
    # filepath = "/Users/dineshgadu/Desktop/PCS Project" + filename + ".txt"
    #
    # if not os.path.exists("/Users/dineshgadu/Desktop/PCS Project"):
    #     os.makedirs("/Users/dineshgadu/Desktop/PCS Project")
    try:
        c.execute("SELECT cre FROM acess_control WHERE username=%s", (username,))
        access = c.fetchone()
        # print(access)
        if (access[0] == 1):
            with open("/Users/dineshgadu/Desktop/PCS Project/"+filename+".txt", 'w') as f:
                data="File created successfully!"
                client.send(data.encode('utf-8'))
                transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                # print(transaction_time);
                sql = "INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)"
                val = (username, filename, "create", transaction_time)
                c.execute(sql, val)
                cnx.commit()
        else:
            print("You don't have permission!")
    except Exception as e:
        print("Error creating file:", e)
    # filename = input("Enter a filename: ")
    # /Users/dineshgadu/Desktop/PCS Project
    # path = os.path.join("Users", "Desktop", "files", filename)
    # f = open(path, "w")
    # f.close()
    # transaction_time = datetime.datetime.now()

    # c.execute("INSERT INTO transactions (id,username, filename, transaction_type, transaction_time) VALUES (%d, %s, %s, %s,%s)",(1,username, filename, "create", transaction_time))

    # print(f"File '{filename}' created successfully.")



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