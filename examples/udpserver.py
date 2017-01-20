from socket import *

serverPort = 12122

serverAddress = ''
#serverAddress = 'kobuss-air.uconnect.utah.edu'

serverSocket = socket(AF_INET, SOCK_DGRAM)

print 'Bound to:', serverSocket.getsockname()

serverSocket.bind((serverAddress, serverPort))

print 'Bound to:', serverSocket.getsockname()

print "server ready:"

while True:
    print "Waiting for customers"
    message, clientAddress = serverSocket.recvfrom(2048)
    print "We got:", message, "From:", clientAddress
    modifiedMessage = message.upper()
    serverSocket.sendto(modifiedMessage, clientAddress)
    print "Done with this one"

