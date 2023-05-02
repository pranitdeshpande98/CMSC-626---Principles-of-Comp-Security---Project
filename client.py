import sys
import os
import threading
import pickle
from socket import *
import mysql.connector
import datetime
import time
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

replica_servers = [("127.0.0.1", 65442),("127.0.0.1", 65443),("127.0.0.1", 65444)]
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
            start_time = time.time()
            while True:
                command = int(input("Enter a command (1. Create, 2. Read, 3. Write, 4. Restore, 5. Delete 6. exit): "))
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
                    else:
                        print("Okay!!")
                elif command == 2:
                    message = username + ':read'
                    client.send(message.encode('utf-8'))
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    client.send(filename_encrypted)
                    data_encrypted = client.recv(65536)
                    print("The encrypted data using RSA algorithm: ",data_encrypted)
                    cipher = PKCS1_OAEP.new(private_key)
                    data = cipher.decrypt(data_encrypted).decode('utf-8')
                    print("The Decrypted data using User's private key of RSA:", data)
                    read_message = client.recv(1024)
                    print(read_message)
                elif command == 3:
                    message = username + ':write'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    # client.recv(1024).decode('utf-8')
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
                    end_time = time.time()
                    execution_time = end_time - start_time
                    print("Total execution time: {:.2f} seconds".format(execution_time))
                    exit(0)
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
def create_file(username):
    x = "please send me the file name that you wanted to create ";
    client.send(x.encode('utf-8'))
    filename_encrypted = client.recv(1024).decode('utf-8')
    filename = filename_encrypted;
    # filepath = "/Users/dineshgadu/Desktop/PCS Project" + filename + ".txt"
    #
    # if not os.path.exists("/Users/dineshgadu/Desktop/PCS Project"):
    #     os.makedirs("/Users/dineshgadu/Desktop/PCS Project")
    try:
        c.execute("SELECT cre FROM acess_control WHERE username=%s and file_id=%s", (username,1))
        access = c.fetchone()
        # print(access)
        if (access[0] == 1):
            with open("/Users/dineshgadu/Desktop/PCS Project/"+filename+".txt", 'w') as f:
                data="File created successfully!"
                # file_id = c.lastrowid
                client.send(data.encode('utf-8'))
                transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(transaction_time);

                sql1 = "INSERT INTO files (filename,owner) VALUES (%s, %s)"
                val1 = (filename, username)
                print("inserting...")
                c.execute(sql1, val1)
                print("inserted...")
                cnx.commit()
                print("commited...")
                c.execute("SELECT file_id FROM files WHERE filename=%s", (filename,))
                row = c.fetchone()
                file_id = row[0]
                print(file_id)
                client.send(str(file_id).encode('utf-8'))
                cnx.commit()
                c.execute("select public_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)",(username, username))
                other_user_pub_key = c.fetchone()[0]
                # print(other_user_pub_key);
                c.execute("select private_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)",(username, username))
                other_user_pri_key = c.fetchone()[0]
                # print(other_user_pri_key);
                c.execute("INSERT INTO acess_control (public_key,private_key,username,re,wr,delet,cre,rest,file_id) values(%s,%s,%s,%s,%s,%s,%s,%s,%s)",(other_user_pub_key, other_user_pri_key, username, 1, 1, 1, 1, 1, file_id));
                sql = "INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)"
                val = (username, filename, "create", transaction_time)
                c.execute(sql, val)
                cnx.commit()
            for replica_server in replica_servers:
                with socket(AF_INET, SOCK_STREAM) as s:
                    s.connect(replica_server)
                    request = ('create', filename,'')
                    s.sendall(pickle.dumps(request))
            #send message to replica
            replica_message = {"filename": filename, "operation": "create"}

            # replica_socket.close()
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

def read_file(username):
    x="please send me the file name";
    client.send(x.encode('utf-8'))
    filename_encrypted = client.recv(1024).decode('utf-8')
    filename = filename_encrypted;
    # filename = client.recv(1024).decode('utf-8')
    c.execute("select private_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)",(username, username))
    result = c.fetchone()[0]
    # result = result.replace('-----BEGIN PRIVATE KEY-----\n', '')
    # result = result.replace('\n-----END PRIVATE KEY-----\n', '')
    privateKeyString = result
    private_key = RSA.import_key(privateKeyString)
    print(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    # filename = cipher.decrypt(filename_encrypted).decode('utf-8')
    # filepath = os.path.join("Dinesh", "desktop", "files", filename)
    try:
        with open("/Users/dineshgadu/Desktop/PCS Project/" + filename + ".txt", 'r') as f:
            data = f.read()
            c.execute("select public_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)",(username, username))
            result = c.fetchone()[0]
            result = result.replace('-----BEGIN RSA PUBLIC KEY-----\n', '')
            result = result.replace('\n-----END RSA PUBLIC KEY-----\n', '')
            public_key_str = result
            public_key_bytes = base64.b64decode(public_key_str)
            public_key = RSA.import_key(public_key_bytes)
            cipher = PKCS1_OAEP.new(public_key)
            # chunk_size = 245
            # data_chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
            # encrypted_chunks = []
            # for chunk in data_chunks:
            #     encrypted_chunk = cipher.encrypt(chunk.encode('utf-8'))
            #     encrypted_chunks.append(encrypted_chunk)
            # # Concatenating encrypted chunks into one long message to send
            # data_encrypted = b"".join(encrypted_chunks)
            data_encrypted = cipher.encrypt(data.encode('utf-8'))
            # Split the encrypted data into chunks of max size 1024
            # chunks = [data_encrypted[i:i + 1024] for i in range(0, len(data_encrypted), 1024)]
            # for chunk in chunks:
            #     client.send(chunk)

            transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            client.send(data_encrypted)
            c.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)",(username, filename, "read", transaction_time))
            cnx.commit()
            read_message = "File read succesfully! ";
            client.send(read_message.encode('utf-8'))
    except Exception as e:
        read_message = "File not found ";
        client.send(read_message.encode('utf-8'))
        print('File not found.', e)

#
def write_file(username):
    x = "please send me the file name to perform write operation ";
    client.send(x.encode('utf-8'))
    filename_encrypted = client.recv(1024).decode('utf-8')
    filename = filename_encrypted;
    try:
        with open("/Users/dineshgadu/Desktop/PCS Project/" + filename + ".txt", 'r+') as f:
            c.execute("select file_id from files where filename=%s",(filename,))
            file_id=c.fetchone()[0]
            c.execute("SELECT wr FROM acess_control WHERE username=%s and file_id=%s", (username,file_id))
            write_access=c.fetchone()[0]
            print(write_access)
            # client.send("1").encode('utf-8')
            if(write_access==1):
                fcntl.flock(f, fcntl.LOCK_EX)
                data = f.read()
                c.execute("select public_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)", (username, username))
                result = c.fetchone()[0]
                result = result.replace('-----BEGIN RSA PUBLIC KEY-----\n', '')
                result = result.replace('\n-----END RSA PUBLIC KEY-----\n', '')
                public_key_str = result
                public_key_bytes = base64.b64decode(public_key_str)
                public_key = RSA.import_key(public_key_bytes)
                cipher = PKCS1_OAEP.new(public_key)
                data_encrypted = cipher.encrypt(data.encode('utf-8'))
                client.send(data_encrypted)
                data2 = client.recv(1024)
                new_data = data2.decode('utf-8')
                f.seek(0,os.SEEK_END)
                f.write(new_data)
                f.truncate()
                write_message="File written successfully";
                client.send(write_message.encode('utf-8'))
                # release lock on file
                fcntl.flock(f, fcntl.LOCK_UN)
                replication_data = new_data.encode('utf-8')
                for replica_server in replica_servers:
                    with socket(AF_INET, SOCK_STREAM) as s:
                        s.connect(replica_server)
                        request = ('write', filename, replication_data)
                        s.sendall(pickle.dumps(request))
                transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                c.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)",(username, filename, "write", transaction_time))
                cnx.commit()
            else:
                write_message = "you don't have permission to write!";
                client.send(write_message.encode('utf-8'))
    except Exception as e:
        write_message = "File not found ";
        client.send(write_message.encode('utf-8'))
        print('File not found.', e)

def restore_file(username):
    x = "please send me the file name that you want to restore ";
    client.send(x.encode('utf-8'))
    filename_encrypted = client.recv(1024).decode('utf-8')
    filename = filename_encrypted;
    try:
        with open("/Users/dineshgadu/Desktop/PCS Project/restore_files/" + filename + ".txt", 'r+') as f:
            c.execute("select file_id from files where filename=%s", (filename,))
            file_id = c.fetchone()[0]
            c.execute("SELECT rest FROM acess_control WHERE username=%s and file_id=%s", (username,file_id))
            access = c.fetchone()
            # print(access)
            if (access[0] == 1):
                src_path = "/Users/dineshgadu/Desktop/PCS Project/restore_files/"+ filename + ".txt"
                dest_path = "/Users/dineshgadu/Desktop/PCS Project/"+ filename + ".txt"
                shutil.copy(src_path, dest_path)
                transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                c.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)",(username, filename, "restore", transaction_time))
                cnx.commit()
                restore_message = "File restored successfully"
                client.send(restore_message.encode('utf-8'))
                data = f.read()
                replication_data = data.encode('utf-8')
                for replica_server in replica_servers:
                    with socket(AF_INET, SOCK_STREAM) as s:
                        s.connect(replica_server)
                        request = ('restore', filename, replication_data)
                        s.sendall(pickle.dumps(request))
            else:
                restore_message = "you don't have permission to restore!";
                client.send(restore_message.encode('utf-8'))
    except Exception as e:
        restore_message = "File not found ";
        client.send(restore_message.encode('utf-8'))
        print('File not found.', e)

def delete_file(username):
    x = "please send me the file name that you want to restore ";
    client.send(x.encode('utf-8'))
    filename_encrypted = client.recv(1024).decode('utf-8')
    filename = filename_encrypted;
    # filepath = os.path.join("Users","dineshgadu", "Desktop","PCS Project", filename,".txt")
    try:
        # with open("/Users/dineshgadu/Desktop/PCS Project/" + filename + ".txt", 'r') as f:
    # c.execute("SELECT * FROM transactions WHERE filename=?", (filename,))
    # if c.fetchone() is
    # if os.path.exists(filepath):
        c.execute("select file_id from files where filename=%s", (filename,))
        file_id = c.fetchone()[0]
        print(file_id)
        c.execute("SELECT delet FROM acess_control WHERE username=%s and file_id=%s", (username,file_id))
        access = c.fetchone()
        # print(access)
        if (access[0] == 1):
            src_path = "/Users/dineshgadu/Desktop/PCS Project/" + filename + ".txt"
            dest_path = "/Users/dineshgadu/Desktop/PCS Project/restore_files/" + filename + ".txt"
            shutil.move(src_path, dest_path)
            # os.remove("/Users/dineshgadu/Desktop/PCS Project/" + filename + ".txt")
            transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)",(username, filename, "delete", transaction_time))
            cnx.commit()
            delete_message = "File deleted!"
            client.send(delete_message.encode('utf-8'))
            for replica_server in replica_servers:
                with socket(AF_INET, SOCK_STREAM) as s:
                    s.connect(replica_server)
                    request = ('delete', filename, '')
                    s.sendall(pickle.dumps(request))
        else:
            delete_message = "You don't have permission to perform delete operation!"
            client.send(delete_message.encode('utf-8'))
    except Exception as e:
        delete_message = "File not found! "
        client.send(delete_message.encode('utf-8'))
        print('File not found.', e)

# def create_connection():
#     client_address = '127.0.0.1'
#     client_port = 65452
#     client = socket(AF_INET, SOCK_STREAM)
#     client.connect((client_address, client_port))
#     print("Connection Sucess!!")
#     client.send("Hi I am client".encode('utf-8'))
#     data = client.recv(1024)
#     print(data.decode('utf-8'))
cnx = mysql.connector.connect(user='dinesh', password='dinesh',
                                             host='127.0.0.1',
                                             database='pcs',auth_plugin='mysql_native_password')
c = cnx.cursor();
print("1. Server 2. Client")
choose=int(input())
if(choose==2):
    client_address = '127.0.0.1'
    client_port = 65485
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
        # cnx = mysql.connector.connect(user='dinesh', password='dinesh',
        #                                  host='127.0.0.1',
        #                                  database='pcs')
        # # print("Database is connected!!")
        # # c=cnx.cursor()
        # # username='u1'
        # # password='p1'
        # # c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        # # cnx.commit()
        # # print('hi')
        # c = cnx.cursor();
        choice = int(input())
        if choice == 1:
            register()
            login()
        elif choice==2:
            login()
        elif choice==3:
            change_key();
        else:
            exit(0)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
else:
    # cnx = mysql.connector.connect(user='dinesh', password='dinesh',
    #                               host='127.0.0.1',
    #                               database='pcs', auth_plugin='mysql_native_password')
    # c = cnx.cursor();
    server_address = '127.0.0.1'
    server_port = 65485
    serv = socket(AF_INET, SOCK_STREAM)
    serv.bind((server_address, server_port))
    serv.listen(25)
    client, address = serv.accept()
    data = client.recv(1024)
    print(data.decode('utf-8'))
    client.send("Hi I am server".encode('utf-8'))
    while True:
        try:
            data = client.recv(1024).decode('utf-8')
            username, command = data.split(':')
            print(username)
            print(command)
            if command == "create":
                create_file(username)
            elif command == "read":
                read_file(username)
            elif command == "write":
                print("dinesh")
                write_file(username)
            elif command == "restore":
                restore_file(username)
            elif command == "delete":
                delete_file(username)
            else:
                print("sorry invalid command")
        except:
            pass
    # serv.close()
