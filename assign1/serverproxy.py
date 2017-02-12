#!/usr/bin/python3
##############
# Alec Adair
# CS4480 PA1-A
##############

from socket import *
from urllib.parse import urlparse
import sys
import multiprocessing
import hashlib
import re

def handle_client(client_socket, client_addr):
    while (1):
        data = client_socket.recv(4096)
        try:
            message = data.decode('utf-8')
        except Exception:
            break
        msg_list = message.split()
        if (len(msg_list) == 0):
            break
        if (msg_list[0] != 'GET'):
            not_impl = 'Not Implemented (501) error (see RFC 1945 section 9.5 - Server Error)'
            client_socket.sendall(not_impl.encode())
        elif (len(msg_list) > 3):  # must be browser
            web_sock = socket(AF_INET, SOCK_STREAM)
            url_par = urlparse(msg_list[1])
            web_sock.connect((url_par.hostname, 80))
            to_send = message.encode()
            web_sock.sendall(to_send)
            buff = web_sock.recv(4096)
            client_socket.sendall(buff)
            temp = buff
            while (len(buff) > 0):
                buff = web_sock.recv(4096)
                try:
                    client_socket.sendall(buff)
                except Exception:
                    break
            web_sock.close()
        else:
            host = ''
            client_message = client_socket.recv(4096)
            header_list = ''
            decode = client_message.decode('utf-8')
            while (client_message.decode('utf-8') != '\r\n' and len(client_message) > 0):
                message = client_message.decode('utf-8')
                header = message.split()
                if (header[0] == 'Host:'):
                    host = header[1]
                else:
                    header_list += message
                client_message = client_socket.recv(4096)
                print(client_message.decode('utf-8'))
            url_parser = urlparse(msg_list[1])
            if (url_parser.hostname):  # absolute path
                http_request(url_parser.hostname, url_parser.path, header_list)
            else:  # relative path
                http_request(host, msg_list[1], header_list)


def create_md5_from_bytes(bytes_object):
    m = hashlib.md5()
    m.update(bytes_object)
    md5_hash = m.hexdigest()
    return md5_hash


def hash_is_virus(md5_hashcode):
    cymru_socket = socket(AF_INET, SOCK_STREAM)
    cymru_socket.connect(('hash.cymru.com', 43))
    #message_to_send = md5_hashcode.encode()
    message_to_send = md5_hashcode + '\r\n'
    cymru_socket.sendall(message_to_send.encode('utf-8'))
    h_code = cymru_socket.recv(4096)
    if(b'NO_DATA' in h_code):
        return 'False'
    else:
        return 'True'
    #print(h_code.decode())
    #return h_code

#def is_line_http_header(line):
    

def http_request(host_name, path, headers):
    http_port = 80
    web_socket = socket(AF_INET, SOCK_STREAM)
    try:
        web_socket.connect((host_name, http_port))
    except Exception:
        return
    message = 'GET ' + path + ' HTTP/1.0\n\nHost: ' + host_name + '\n' + headers
    print(message)
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
    html_text, separator, binary = web_buffer.partition(b'\r\n\r\n')
    if(binary == b''):
        md5_code = create_md5_from_bytes(html_text)
    else:
        md5_code = create_md5_from_bytes(binary)
    md5_status = hash_is_virus(md5_code)
    if (md5_status == 'True'):
        client_socket.sendall(b'malware\r\n')
    else:
        client_socket.sendall(web_buffer)
    web_socket.close()


#############
# Main Method
#############
if __name__ == '__main__':
    args = sys.argv
    server_port = 12000
    if (len(args) == 2):
        server_port = int(args[1])
    host = 'localhost'
    server_socket = socket(AF_INET, SOCK_STREAM)
    try:
        server_socket.bind(('', server_port))
        server_socket.listen(1)
    except Exception:
        print('couldn\'t bind socket')
    print('Server ready to receive on port', server_port)

    while True:
        client_socket, con_addr = server_socket.accept()
        print('proxy connected to client: ' + con_addr[0] + ' : ' + str(con_addr[1]))
        process = multiprocessing.Process(target=handle_client, args=(client_socket, con_addr))
        process.start()
        print('running process: ' + con_addr[0] + ':' + str(con_addr[1]))
