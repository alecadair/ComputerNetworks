#!/usr/bin/python3
##############
# Alec Adair
# CS4480 PA1
##############

from socket import *
import sys, getopt

def handle_client(client_socket,client_addr):
  client_socket.send(str.encode('do you hear this?\n'))
  while(1):
    data = client_socket.recv(4096)
    message = data.decode('utf-8')
    if(len(message) == 0):
      break;
    print('received message back')
    print(message)
    msg_list = message.split()
    print(msg_list)
    if(msg_list[0] != 'GET'):
      print('Proxy cannot handle this type of request')
  
  socket.close()

print (sys.argv)
args = sys.argv
print (args)
server_port = 12000
if(len(args) == 2):
  server_port = int(args[1])
print (server_port + 1)
host = 'localhost'
server_socket = socket(AF_INET,SOCK_STREAM)
try:
  server_socket.bind(('',server_port))
  server_socket.listen(1)
except socket.error as e:
  print(str(e))
print('Server ready to receive on port',server_port)

while True:
  client_socket, con_addr = server_socket.accept()
  print('proxy connect to client: ' + con_addr[0] + ' : ' + str(con_addr[1]))
  handle_client(client_socket,con_addr)

