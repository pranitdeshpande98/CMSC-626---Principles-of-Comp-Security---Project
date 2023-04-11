import sys
import threading
from socket import *
def create_connection():
    client_address = '127.0.0.1'
    client_port = 65432
    client = socket(AF_INET, SOCK_STREAM)
    client.connect((client_address, client_port))
    print("Connection Sucess!!")
    client.send("Hi I am client".encode('utf-8'))
    data = client.recv(1024)
    print(data.decode('utf-8'))
    client.close()


def change_key(username):



if __name__ == "__main__":

    print("Please choose an options")
    print("1 - Register with server")
    print("2 - Login and make connection with the server")
    print("3- Change Key")
    input_client= int(input())
    if(input_client==2):
        create_connection()
    elif(input_client==3):
        print("Enter the user name: ")
        user_name=input()
        value=change_key(user_name)
        if(value==0):
            print("User name is not valid! Please make new connection with the server")

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
        sql = "INSERT INTO acess_control (public_key, private_key, username, re, wr, delet, cre, rest) VALUES (%s, %s, %s,%s, %s, %s, %s, %s)"
        val = (public_key.decode('utf-8'), private_key.decode('utf-8'), username, 1,1,0,1,0)
        c.execute(sql, val)
        cnx.commit()


def restore_file(username):
    filename = input("Enter a filename: ")
    try:
        with open("/Users/dineshgadu/Desktop/PCS Project/restore_files/" + filename + ".txt", 'r+') as f:
            c.execute("SELECT rest FROM acess_control WHERE username=%s", (username,))
            access = c.fetchone()
            # print(access)
            if (access[0] == 1):
                src_path = "/Users/dineshgadu/Desktop/PCS Project/restore_files/"+ filename + ".txt"
                dest_path = "/Users/dineshgadu/Desktop/PCS Project/"+ filename + ".txt"
                shutil.copy(src_path, dest_path)
                transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                c.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)",(username, filename, "restore", transaction_time))
                cnx.commit()
                print("File restored successfully")
            else:
                print("you don't have permission to restore!")
    except Exception as e:
        print("Error Restoring file:", e)
        
        
def delete_file(username):
    filename = input("Enter a filename: ")
    # filepath = os.path.join("Users","dineshgadu", "Desktop","PCS Project", filename,".txt")
    try:
        # with open("/Users/dineshgadu/Desktop/PCS Project/" + filename + ".txt", 'r') as f:
    # c.execute("SELECT * FROM transactions WHERE filename=?", (filename,))
    # if c.fetchone() is
    # if os.path.exists(filepath):
        c.execute("SELECT delet FROM acess_control WHERE username=%s", (username,))
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
            print('File deleted!')
        else:
            print("you don't have permission to delete!")
    except Exception as e:
        print('File not found.', e)



