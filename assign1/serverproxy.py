#!/usr/bin/python3
#############
# Alec Adair
# CS4480 PA1
#############
from socket import *
from urllib.parse import urlparse
import sys
import multiprocessing
import hashlib


# called by the main loop on a new thread for each client connected to proxy-server
def handle_client(client_socket, client_addr):
    while (1):
        # receive client http request
        data = client_socket.recv(4096)
        try:
            # decode message
            message = data.decode('utf-8')
        except Exception:
            break
        # split message into space seperated tokens
        msg_list = message.split()
        if (len(msg_list) == 0):
            break
        # check that the client sent a valid GET request
        if (msg_list[0] != 'GET'):
            # send error not valid GET requuest
            not_impl = 'Not Implemented (501) error (see RFC 1945 section 9.5 - Server Error)\r\n'
            client_socket.sendall(not_impl.encode())
        # if client sent GET with more than 3 arguments, client is probably a web-browser
        elif (len(msg_list) > 3):
            # create a new socket to connect to client requested web-server
            web_sock = socket(AF_INET, SOCK_STREAM)
            url_par = urlparse(msg_list[1])
            # connect socket to port 80(HTTP port)
            web_sock.connect((url_par.hostname, 80))
            # send the web server the clients request
            to_send = message.encode()
            web_sock.sendall(to_send)
            buff = web_sock.recv(4096)
            client_socket.sendall(buff)
            browser_buff = bytearray()
            browser_buff.extend(buff)
            # be sure to send entire client message
            while (len(buff) > 0):
                try:
                    web_sock.settimeout(1.0)
                    buff = web_sock.recv(4096)
                    browser_buff.extend(buff)
                    client_socket.sendall(buff)
                except Exception:
                    break
            #client_socket.sendall(browser_buff)
            # close socket
            #client_socket.sendall(b'\r\n')
            web_sock.close()
        # client is probably telnet
        else:
            host = ''
            # receive the client message
            client_message = client_socket.recv(4096)
            header_list = ''
            decode = client_message.decode('utf-8')
            # be sure to receive the entire client message
            while (client_message.decode('utf-8') != '\r\n' and len(client_message) > 0):
                message = client_message.decode('utf-8')
                header = message.split()
                # check for the host header
                if (header[0] == 'Host:'):
                    host = header[1]
                else:
                    header_list += message
                client_message = client_socket.recv(4096)
            url_parser = urlparse(msg_list[1])
            # http_request with absolute path
            if (url_parser.hostname):
                http_request(url_parser.hostname, url_parser.path, header_list)
            # http_request with relative path
            else:
                http_request(host, msg_list[1], header_list)


# create an md5 hash for a given string of bytes
def create_md5_from_bytes(bytes_object):
    m = hashlib.md5()
    m.update(bytes_object)
    md5_hash = m.hexdigest()
    return md5_hash


# query cymru hash registry for given md5 hash
def hash_is_virus(md5_hashcode):
    cymru_socket = socket(AF_INET, SOCK_STREAM)
    cymru_socket.connect(('hash.cymru.com', 43))
    message_to_send = md5_hashcode + '\r\n'
    cymru_socket.sendall(message_to_send.encode('utf-8'))
    h_code = cymru_socket.recv(4096)
    if (b'NO_DATA' in h_code):
        return 'False'
    else:
        return 'True'


# perform http_request for given host_name, path, and headers
# this function also checks for malware in the response from the web-server
def http_request(host_name, path, headers):
    # connect to http server using host name and port 80
    http_port = 80
    web_socket = socket(AF_INET, SOCK_STREAM)
    try:
        web_socket.connect((host_name, http_port))
    except Exception:
        # if connection doesn't work send error message and exit function
        err_msg = 'Proxy could not connect to requested host: ' + host_name + '\r\n'
        client_socket.sendall(err_msg.encode('utf-8'))
        return
    # construct and send http request
    message = 'GET ' + path + ' HTTP/1.0\n\nHost: ' + host_name + '\n' + headers
    web_socket.sendall(message.encode())
    web_buffer = bytearray()
    buff = web_socket.recv(4096)
    web_buffer.extend(buff)
    while (len(buff) > 0):
        try:
            buff = web_socket.recv(4096)
            web_buffer.extend(buff)
        except Exception:
            break
    # parse web response into html text, the seperator for objects, and a possible binary executable
    html_text, separator, binary = web_buffer.partition(b'\r\n\r\n')
    # create md5 hash for the web object received
    # if binary is empty the web server sent no html headers and just a plain binary
    if (binary == b''):
        md5_code = create_md5_from_bytes(html_text)
    # if binary is not empty, the web server sent html headers
    else:
        md5_code = create_md5_from_bytes(binary)
    # check if md5 hash is in cymru registry
    md5_status = hash_is_virus(md5_code)
    # if malware detected report to client, otherwise send content to client
    if (md5_status == 'True'):
        client_socket.sendall(b'malware\r\n')
    else:
        client_socket.sendall(web_buffer)
        client_socket.sendall(b'\r\n')
    # close the connection with the web servers
    web_socket.close()


#############
# Main Method
#############
if __name__ == '__main__':
    # if argv is empty set port to 1200, otherwise set port to argument
    args = sys.argv
    server_port = 12000
    if (len(args) == 2):
        server_port = int(args[1])
    # set listening server socket host to localhost and create socket
    host = 'localhost'
    server_socket = socket(AF_INET, SOCK_STREAM)
    # try to bind socket and listen for connections
    try:
        server_socket.bind(('', server_port))
        server_socket.listen(1)
    except Exception:
        print('couldn\'t bind socket')
        exit(-1)
    print('Server ready to receive on port', server_port)
    while True:
        # accept connection create a new process with handle_client method and send client to new process
        client_socket, con_addr = server_socket.accept()
        print('proxy connected to client: ' + con_addr[0] + ' : ' + str(con_addr[1]))
        process = multiprocessing.Process(target=handle_client, args=(client_socket, con_addr))
        process.start()
        print('running process: ' + con_addr[0] + ':' + str(con_addr[1]))
