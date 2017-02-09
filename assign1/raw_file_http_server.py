#!/usr/bin/python3

#Author: Alec Adair

from socket import *
import sys


server_socket = socket(AF_INET, SOCK_STREAM)
try:
    server_socket.bind(('', 2113))
    server_socket.listen(1)
except Exception:
    print('could not bind socket')
print('Ready to receive on port 2113')
while True:
    client_socket, con_addr = server_socket.accept()
    print('server connected to client: ' + con_addr[0] + ':' +str(con_addr[1]))
    client_socket.recv(4096)
    with open("/Users/alecadair/131.exe",'rb') as f:
        client_socket.sendall(f.read())
    client_socket.close()
