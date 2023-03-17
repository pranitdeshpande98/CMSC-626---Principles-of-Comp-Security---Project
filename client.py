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



