from socket import *

serverAddress = ''
#serverAddress = 'localhost'
#serverAddress = 'kobuss-air.uconnect.utah.edu'
serverPort = 12122

clientSocket = socket(AF_INET, SOCK_DGRAM)

# explicit bound port on client side
#clientPort = 22222
#clientSocket.bind(('',clientPort))

# explicit bound port and address
#clientAddress = 'localhost'
#clientAddress = 'kobuss-air.uconnect.utah.edu'
#clientSocket.bind((clientAddress,clientPort))

print 'Bound to (after socket call):', clientSocket.getsockname()

message = raw_input('input please:')


print 'Sending to:', serverAddress
clientSocket.sendto(message, (serverAddress, serverPort))
print 'Bound to (after send call):', clientSocket.getsockname()

modifiedMessage, serverAddress = clientSocket.recvfrom(2048)

print 'Bound to (after revfrom):', clientSocket.getsockname()

print 'We got:', modifiedMessage

# wait before closing socket
message = raw_input('enter to finsh')

clientSocket.close()

