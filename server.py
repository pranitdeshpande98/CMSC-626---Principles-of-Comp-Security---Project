import sys
import os
import pickle
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
import base64
import getpass_asterisk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

replica_servers = [("127.0.0.1", 65442),("127.0.0.1", 65443),("127.0.0.1", 65444)]

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

cnx = mysql.connector.connect(user='dinesh', password='dinesh',
                                         host='127.0.0.1',
                                         database='pcs',auth_plugin='mysql_native_password')
c = cnx.cursor();
server_address = '127.0.0.1'
server_port = 65477
serv = socket(AF_INET,SOCK_STREAM)
serv.bind((server_address, server_port))
serv.listen(25)
client, address = serv.accept()
data=client.recv(1024)
print(data.decode('utf-8'))
client.send("Hi I am server".encode('utf-8'))
while True:
    try:
        data = client.recv(1024).decode('utf-8')
        username, command  = data.split(':')
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
