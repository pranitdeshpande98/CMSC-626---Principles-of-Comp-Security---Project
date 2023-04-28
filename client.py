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
import base64
from Crypto.Util import asn1
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def register():
    username = input("Enter new username: ")
    password = input("Enter new password: ")
    c.execute("SELECT * FROM users WHERE username=%s", (username,))
    if c.fetchone() is not None:
        print("Username already exists")
    else:
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        c.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password_hash))
        cnx.commit()
        print("User created successfully")
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
        private_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,serialization.NoEncryption())

        sql = "INSERT INTO acess_control (public_key, private_key, username, re, wr, delet, cre, rest,file_id) VALUES (%s, %s, %s,%s, %s, %s, %s, %s,%s)"

        val = (public_key.decode('utf-8'), private_key.decode('utf-8'), username, 1,1,1,1,1,1)
        c.execute(sql, val)
        cnx.commit()

def login():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize the public and private keys to PEM format
    public_key_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Load the public key from the PEM-encoded string
    rsa_public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    username = input("Enter username: ")
    password = input("Enter password: ")
    # password = getpass_asterisk.getpass("Enter password: ")
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    c.execute("SELECT password FROM users WHERE username=%s", (username,))
    result = c.fetchone()
    # c.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
    if result is None:
        print("Username or password is incorrect")
    else:
        stored_password_hash = result[0]
        if password_hash == stored_password_hash:
            print("Login successfull ! connecting to the server..")
            c.execute("select public_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)",(username, username))
            result = c.fetchone()[0]
            result = result.replace('-----BEGIN RSA PUBLIC KEY-----\n', '')
            result = result.replace('\n-----END RSA PUBLIC KEY-----\n', '')
            public_key_str = result
            public_key_bytes = base64.b64decode(public_key_str)
            public_key = RSA.import_key(public_key_bytes)
            c.execute("select private_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)",(username, username))
            result = c.fetchone()[0]
            # result = result.replace('-----BEGIN PRIVATE KEY-----\n', '')
            # result = result.replace('\n-----END PRIVATE KEY-----\n', '')
            privateKeyString = result
            private_key = RSA.import_key(privateKeyString)
            while True:
                command = int(input("Enter a command (1. Create, 2. Read, 3. Write, 4. Restore, 5. Delete): "))
                if command == 1:
                    message = username + ':create'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input("Enter a file name: ")
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    data = client.recv(1024)
                    print(data)
                    set_permissions = input("Do you want to set permissions for other users? (y/n) ")
                    if set_permissions.lower() == 'y':
                        other_username = input("Enter the username of the user you want to give permissions to: ")
                        # c.execute("select public_key from acess_control where username=%s",(other_username,))
                        # other_user_pub_key = c.fetchone()
                        # other_user_pri_key =
                        c.execute("SELECT * FROM users WHERE username=%s", (other_username,))
                        if c.fetchone() is not None:
                            print(filename);
                            file_id = int(client.recv(1024).decode('utf-8'))
                            print(file_id)
                            # c.execute("SELECT file_id FROM files WHERE filename=%s", ('kp',))
                            # row = c.fetchone()
                            # file_id = row[0]
                            # print(row)
                            print("Enter the permissions you want to grant (read, write, delete, create, restore): ")
                            re = int(input())
                            wr = int(input())
                            delet = int(input())
                            cre = int(input())
                            rest = int(input())
                            c.execute("select public_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)", (other_username,other_username))
                            other_user_pub_key = c.fetchone()[0]
                            # print(other_user_pub_key);
                            c.execute("select private_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)", (other_username,other_username))
                            other_user_pri_key = c.fetchone()[0]
                            # print(other_user_pri_key);
                            c.execute("INSERT INTO acess_control (public_key,private_key,username,re,wr,delet,cre,rest,file_id) values(%s,%s,%s,%s,%s,%s,%s,%s,%s)",(other_user_pub_key,other_user_pri_key,other_username,re, wr, delet, cre, rest, file_id));
                            # c.execute("UPDATE acess_control SET re = %s,wr = %s,delet = %s,cre = %s,rest = %s,file_id = %s where username=%s", (re, wr, delet, cre, rest, file_id,other_username))
                            cnx.commit()
                elif command == 2:
                    message = username + ':read'
                    client.send(message.encode('utf-8'))
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    client.send(filename_encrypted)
                    data_encrypted = client.recv(1024)
                    print("The encrypted data using RSA algorithm: ",data_encrypted)
                    cipher = PKCS1_OAEP.new(private_key)
                    data = cipher.decrypt(data_encrypted).decode('utf-8')
                    print("The Decrypted data using User's private key of RSA:", data)
                elif command == 3:
                    message = username + ':write'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    flag = client.recv(1024).decode('utf-8')
                    data_encrypted = client.recv(1024)
                    print("The encrypted data using RSA algorithm: ", data_encrypted)
                    cipher = PKCS1_OAEP.new(private_key)
                    data = cipher.decrypt(data_encrypted).decode('utf-8')
                    print("The Current content and Decrypted data using User's private key of RSA:", data)
                    new_data = input("Enter new content that you want to add: ")
                    client.send(new_data.encode('utf-8'))
                    write_message = client.recv(1024)
                    print(write_message)
                elif command == 4:
                    message = username + ':restore'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    data = client.recv(1024)
                    print(data)
                elif command == 5:
                    message = username + ':delete'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    data = client.recv(1024)
                    print(data)
                else:
                    print("Invalid command, please try again")
        else:
            print("Username or password is incorrect")
def change_key():
    username = input("Enter username: ")
    password = input("Enter password: ")
    c.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
    if c.fetchone() is None:
        print("Username or password is incorrect")
    else:
        print("Generating new pair of public and private keys")
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
        private_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        # c.execute("UPDATE acess_control SET public_key=public_key.decode('utf-8') AND private_key=private_key.decode('utf-8') WHERE username=%s", (username,))
        sql = "UPDATE acess_control SET public_key=%s, private_key=%s WHERE username=%s"
        val = (public_key.decode('utf-8'), private_key.decode('utf-8'), username)
        c.execute(sql, val)
        cnx.commit()

# def create_connection():
#     client_address = '127.0.0.1'
#     client_port = 65452
#     client = socket(AF_INET, SOCK_STREAM)
#     client.connect((client_address, client_port))
#     print("Connection Sucess!!")
#     client.send("Hi I am client".encode('utf-8'))
#     data = client.recv(1024)
#     print(data.decode('utf-8'))


# def read_file(username):
client_address = '127.0.0.1'
client_port = 65466
client = socket(AF_INET, SOCK_STREAM)
client.connect((client_address, client_port))
print("Select the server you want to connect with: 1.Primary server 2.Replica server1 3.Replica server2 4.Replica server3")
d = int(input())
if(d==1):
    print("Connection Sucess with Primary server!!")
elif(d==2):
    print("Connection Sucess with Replica server1!!")
elif(d==3):
    print("Connection Sucess with Replica server2!!")
elif(d==4):
    print("Connection Sucess with Replica server3!!")
else:
    print("Please select valid server to connect")
client.send("Hi I am client".encode('utf-8'))
data = client.recv(1024)
print(data.decode('utf-8'))
print("Please choose an options")
print("1 - Register with server")
print("2 - Login and make connection with the server")
print("3- Change Key")
# create_connection()
#database connection
try:
    cnx = mysql.connector.connect(user='dinesh', password='dinesh',
                                     host='127.0.0.1',
                                     database='pcs')
    # print("Database is connected!!")
    # c=cnx.cursor()
    # username='u1'
    # password='p1'
    # c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    # cnx.commit()
    # print('hi')
    c = cnx.cursor();
    choice = int(input())
    if choice == 1:
        register()
    elif choice==2:
        login()
    elif choice==3:
        change_key();
    else:
        print("hi")
except mysql.connector.Error as err:
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
        print("Something is wrong with your user name or password")
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
        print("Database does not exist")
    else:
        print(err)
